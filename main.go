package main

import (
	"bytes"
	"encoding/json"
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
	"github.com/joho/godotenv"
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
	err := godotenv.Load()
	if err != nil {
		log.Println("[ENV] .env file not found or failed to load (will use OS environment variables)")
	}

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

			if len(tx.MatchedRules()) > 0 {
				rule := tx.MatchedRules()[0]
				triggeredRule = &RuleDetail{
					ID:  strconv.Itoa(rule.Rule().ID()),
					Msg: rule.Message(),
				}
			}

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(statusCode)
			fmt.Fprintf(w, `
				<html>
					<head><title>Request Blocked by AI WAF Rule</title></head>
					<body style="font-family: sans-serif; color: red; text-align: center; padding-top: 50px;">
					<h1>Request Blocked by AI WAF Rule</h1>
					<p><strong>Reason:</strong> %s</p>
					</body>
				</html>
				`, triggeredRule.Msg)

		} else {
			// Read headers
			headers := ""
			for name, values := range r.Header {
				for _, value := range values {
					headers += fmt.Sprintf("%s: %s\n", name, value)
				}
			}

			// Safely read and restore request body (if applicable)
			var bodyStr string
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
				bodyBytes, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // restore body for proxy
				if len(bodyBytes) > 0 {
					bodyStr = string(bodyBytes)
				}
			}

			// Build full request context string
			content := fmt.Sprintf(`
			You are a security model. Analyze the following HTTP request and decide whether to allow or block it.
			Respond with a JSON: {"decision": "allow" or "block", "reason": "short reason"}.

			Method: %s
			URI: %s
			RemoteAddr: %s
			User-Agent: %s

			Headers:
			%s

			Body:
			%s
			`,
				r.Method,
				r.RequestURI,
				r.RemoteAddr,
				r.UserAgent(),
				headers,
				bodyStr,
			)

			softResp, err := check(content)
			if err != nil {
				log.Printf("[SoftCheck] Error: %v", err)
			} else if !softResp.Allow {
				action = "blocked"
				statusCode = 403
				triggeredRule = &RuleDetail{
					ID:  "soft-check",
					Msg: softResp.Reason,
				}
				// http.Error(w, "Blocked by soft-check agent: "+softResp.Reason, statusCode)
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(statusCode)
				fmt.Fprintf(w, `
				<html>
					<head><title>Request Blocked by soft-check agent</title></head>
					<body style="font-family: sans-serif; color: red; text-align: center; padding-top: 50px;">
					<h1>Request Blocked by soft-check agent</h1>
					<p><strong>Reason:</strong> %s</p>
					</body>
				</html>
				`, triggeredRule.Msg)
			} else {
				proxy.ServeHTTP(w, r)
			}
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
