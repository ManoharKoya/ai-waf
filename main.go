package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/fsnotify/fsnotify"
)

var (
	mu         sync.RWMutex
	currentWAF coraza.WAF
)

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func jsonResponse(w http.ResponseWriter, statusCode int, status string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{"status":"%s","message":"%s"}`, status, message)
}

func loadWAF() coraza.WAF {
	rules, err := os.ReadFile("rules.conf")
	if err != nil {
		log.Fatalf("Error reading rules.conf: %v", err)
	}

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(string(rules)))
	if err != nil {
		log.Fatalf("Error creating WAF: %v", err)
	}
	log.Println("[WAF] Rules loaded")
	return waf
}

func watchRules(path string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(path)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				log.Println("[WAF] Detected rules.conf change, reloading...")
				time.Sleep(500 * time.Millisecond)
				newWAF := loadWAF()
				mu.Lock()
				currentWAF = newWAF
				mu.Unlock()
			}
		case err := <-watcher.Errors:
			log.Println("Watcher error:", err)
		}
	}
}

func main() {
	currentWAF = loadWAF()
	go watchRules("rules.conf")

	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:8080"
	}
	backend, _ := url.Parse(backendURL)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = backend.Scheme
			req.URL.Host = backend.Host
		},
	}

	mux := http.NewServeMux()

	// WAF-protected proxy
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		waf := currentWAF
		mu.RUnlock()

		tx := waf.NewTransaction()
		defer tx.Close()

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		tx.ProcessConnection(ip, 0, "localhost", 8080)
		tx.ProcessURI(r.RequestURI, r.Method, r.Proto)

		// Add request headers
		for name, values := range r.Header {
			for _, value := range values {
				tx.AddRequestHeader(name, value)
			}
		}
		tx.ProcessRequestHeaders()

		action := "allowed"
		statusCode := 200
		var triggeredRule *RuleDetail

		if it := tx.Interruption(); it != nil {
			action = "blocked"
			statusCode = it.Status

			// Get matched rule details
			if len(tx.MatchedRules()) > 0 {
				rule := tx.MatchedRules()[0]
				triggeredRule = &RuleDetail{
					ID:  strconv.Itoa(rule.Rule().ID()),
					Msg: rule.Message(),
				}
			}

			http.Error(w, triggeredRule.Msg, statusCode)
		} else {
			proxy.ServeHTTP(w, r)
		}

		publishWAFEvent(WAFEvent{
			Timestamp:     time.Now().UTC(),
			ClientIP:      ip,
			Method:        r.Method,
			URI:           r.RequestURI,
			UserAgent:     r.UserAgent(),
			StatusCode:    statusCode,
			Action:        action,
			RuleTriggered: triggeredRule,
		})
	})

	mux.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonResponse(w, http.StatusMethodNotAllowed, "error", "Only GET supported")
			return
		}

		data, err := os.ReadFile("rules.conf")
		if err != nil {
			jsonResponse(w, 500, "error", "Failed to read rules.conf")
			return
		}

		lines := strings.Split(string(data), "\n")
		var parsedRules []map[string]string
		engineStatus := "Unknown"

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}

			if strings.HasPrefix(trimmed, "SecRuleEngine") {
				// Example: SecRuleEngine On
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					engineStatus = parts[1]
				}
				continue
			}

			if strings.HasPrefix(trimmed, "SecRule") {
				// Expected format: SecRule FIELD OPERATOR "details"
				parts := strings.SplitN(trimmed, " ", 4)
				if len(parts) < 4 {
					continue // skip malformed rules
				}

				rule := map[string]string{
					"field":    parts[1],
					"operator": parts[2],
					"details":  strings.Trim(parts[3], "\""),
				}
				parsedRules = append(parsedRules, rule)
			}
		}

		responseData := map[string]interface{}{
			"status":           "success",
			"rule_engine":      engineStatus,
			"rules_structured": parsedRules,
		}

		response, err := json.MarshalIndent(responseData, "", "  ")
		if err != nil {
			jsonResponse(w, 500, "error", "Failed to encode rules")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(response)
	})

	mux.HandleFunc("/upsert-rule", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonResponse(w, http.StatusMethodNotAllowed, "error", "Only POST supported")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			jsonResponse(w, 500, "error", "Failed to read request body")
			return
		}
		newRule := strings.TrimSpace(string(body))

		// Extract rule ID using regex
		re := regexp.MustCompile(`(?i)\bid\s*:\s*(\d+)`)
		matches := re.FindStringSubmatch(newRule)
		if len(matches) < 2 {
			jsonResponse(w, 400, "error", "Failed to parse rule ID from rule")
			return
		}
		newID := matches[1]

		// Read existing rules
		existingBytes, err := os.ReadFile("rules.conf")
		if err != nil {
			jsonResponse(w, 500, "error", "Failed to read rules.conf")
			return
		}
		existingLines := strings.Split(string(existingBytes), "\n")

		// Replace or append rule
		found := false
		var updatedLines []string
		for _, line := range existingLines {
			if strings.Contains(line, "id:"+newID) || strings.Contains(line, "id: "+newID) {
				updatedLines = append(updatedLines, newRule) // Replace
				found = true
			} else {
				updatedLines = append(updatedLines, line)
			}
		}
		if !found {
			updatedLines = append(updatedLines, newRule)
		}

		finalRules := strings.Join(updatedLines, "\n")

		// Validate combined rules BEFORE writing
		_, err = coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(finalRules))
		if err != nil {
			jsonResponse(w, 400, "error", "Invalid rule syntax: "+err.Error())
			return
		}

		// Save updated rules
		err = os.WriteFile("rules.conf", []byte(finalRules), 0644)
		if err != nil {
			jsonResponse(w, 500, "error", "Failed to write rules.conf")
			return
		}

		log.Printf("[WAF] Rule with id:%s %s\n", newID, ternary(found, "updated", "added"))
		jsonResponse(w, 200, "success", "Rule with id:"+newID+" "+ternary(found, "updated", "added"))
	})

	mux.HandleFunc("/rule/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			jsonResponse(w, http.StatusMethodNotAllowed, "error", "Only DELETE supported")
			return
		}

		id := strings.TrimPrefix(r.URL.Path, "/rule/")
		if id == "" {
			jsonResponse(w, 400, "error", "Missing rule ID in URL")
			return
		}

		content, err := os.ReadFile("rules.conf")
		if err != nil {
			jsonResponse(w, 500, "error", "Failed to read rules.conf")
			return
		}

		lines := strings.Split(string(content), "\n")
		newLines := []string{}
		found := false
		for _, line := range lines {
			if strings.Contains(line, "id:"+id) || strings.Contains(line, "id: "+id) {
				found = true
				continue
			}
			newLines = append(newLines, line)
		}

		if !found {
			jsonResponse(w, 404, "error", "Rule with id:"+id+" not found")
			return
		}

		err = os.WriteFile("rules.conf", []byte(strings.Join(newLines, "\n")), 0644)
		if err != nil {
			jsonResponse(w, 500, "error", "Failed to update rules.conf")
			return
		}

		jsonResponse(w, 200, "success", "Rule with id:"+id+" deleted")
	})

	initProducer([]string{"kafka:9092"})
	log.Println("[WAF] Listening on :8090")
	if err := http.ListenAndServe(":8090", mux); err != nil {
		panic(err)
	}
}
