package main

import (
	"errors"
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

func get_rules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, "error", "Only GET supported")
		return
	}

	data, err := os.ReadFile("rules.conf")
	if err != nil {
		jsonResponse(w, 500, "error", "Failed to read rules.conf")
		return
	}

	re := regexp.MustCompile(`(?i)\bid\s*:\s*(\d+)`)
	matches := re.FindAllStringSubmatch(string(data), -1)

	var ids []string
	for _, match := range matches {
		if len(match) >= 2 {
			ids = append(ids, match[1])
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"success","rules":%q}`, ids)
}

func upsert_rule(newRule string) (int, string, string) {
	// fmt.Println("newRule: ", newRule)
	// Extract rule ID using regex
	id_regex := regexp.MustCompile(`id:(\d+),`)
	get_id := func(ruleString string) (string, error) {
		matches := id_regex.FindStringSubmatch(ruleString)
		// fmt.Println("match length: ", len(matches))
		if len(matches) < 2 {
			return "", errors.New("Error: No ID found in rule: " + ruleString)
		} else if len(matches) > 2 {
			return "", errors.New("Error: Too many ID's found in rule: " + ruleString)
		}
		return matches[1], nil
	}
	newID, idError := get_id(newRule)
	if idError != nil {
		return 400, "Could not parse rule", idError.Error()
	}

	// Read existing rules
	existingBytes, err := os.ReadFile("rules.conf")
	if err != nil {
		return 500, "error", "Failed to read rules.conf"
	}
	existingLines := strings.Split(string(existingBytes), "\n")

	// Replace or append rule
	found := false
	var updatedLines []string
	for _, line := range existingLines {
		// fmt.Println(line)
		id, idError := get_id(line)
		if idError != nil {
			updatedLines = append(updatedLines, line)
			continue
		}
		old_rule_no_id := id_regex.ReplaceAllString(line, "")
		new_rule_no_id := id_regex.ReplaceAllString(newRule, "")
		if id == newID { // replace old rule if new rule has same ID
			updatedLines = append(updatedLines, newRule) // Replace
			found = true
		} else if old_rule_no_id == new_rule_no_id { // remove old rule if new rule has same contents
			continue
		} else { // keep old rule otherwise
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
		return 400, "error", "Invalid rule syntax: " + err.Error()
	}

	// Save updated rules
	err = os.WriteFile("rules.conf", []byte(finalRules), 0644)
	if err != nil {
		return 500, "error", "Failed to write rules.conf"
	}

	log.Printf("[WAF] Rule with id:%s %s\n", newID, ternary(found, "updated", "added"))
	return 200, "success", "Rule with id:" + newID + " " + ternary(found, "updated", "added")
}

func delete_rule(id int) (int, string, string) {
	id_string := strconv.Itoa(id)

	content, err := os.ReadFile("rules.conf")
	if err != nil {
		return 500, "error", "Failed to read rules.conf"
	}

	lines := strings.Split(string(content), "\n")
	newLines := []string{}
	found := false
	for _, line := range lines {
		if strings.Contains(line, "id:"+id_string) || strings.Contains(line, "id: "+id_string) {
			found = true
			continue
		}
		newLines = append(newLines, line)
	}

	if !found {
		return 404, "error", "Rule with id:" + id_string + " not found"
	}

	err = os.WriteFile("rules.conf", []byte(strings.Join(newLines, "\n")), 0644)
	if err != nil {
		return 500, "error", "Failed to update rules.conf"
	}

	return 200, "success", "Rule with id:" + id_string + " deleted"
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

	mux.HandleFunc("/rules", get_rules)

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

		status, header, message := upsert_rule(newRule)
		jsonResponse(w, status, header, message)
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

		id_to_delete, _ := strconv.Atoi(id)
		status, header, message := delete_rule(id_to_delete)

		jsonResponse(w, status, header, message)
	})

	initProducer([]string{"kafka:9092"})
	log.Println("[WAF] Listening on :8090")
	if err := http.ListenAndServe(":8090", mux); err != nil {
		panic(err)
	}
}
