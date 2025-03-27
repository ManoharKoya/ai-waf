package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const azureEndpoint = "https://ai-maroheraai1372357688027.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2025-01-01-preview"

type SoftCheckResult struct {
	Allow  bool
	Reason string
}

func check(content string) (SoftCheckResult, error) {
	apiKey := os.Getenv("AZURE_API_KEY")
	if apiKey == "" {
		return SoftCheckResult{}, errors.New("AZURE_API_KEY not set")
	}

	// Ask the model to respond in a structured format
	userMessage := fmt.Sprintf(`
		You are a web security assistant. 
		Decide whether the following request should be allowed or blocked. 
		Reply in this JSON format only:
		{"decision": "allow" or "block", "reason": "<short reason if blocked>"}

		Request:
		%s
		`, content)

	payload := map[string]interface{}{
		"messages": []map[string]string{
			{"role": "user", "content": userMessage},
		},
		"max_tokens":  128,
		"temperature": 0,
		"top_p":       1,
		"model":       "gpt-4o-mini",
	}

	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", azureEndpoint, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return SoftCheckResult{}, err
	}
	defer resp.Body.Close()

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return SoftCheckResult{}, err
	}

	if len(result.Choices) == 0 {
		return SoftCheckResult{}, errors.New("no result from inference API")
	}

	// Parse model response JSON (e.g., {"decision":"block","reason":"Suspicious user-agent"})
	var response map[string]string
	if err := json.Unmarshal([]byte(result.Choices[0].Message.Content), &response); err != nil {
		return SoftCheckResult{}, errors.New("unexpected format: " + result.Choices[0].Message.Content)
	}

	decision := strings.ToLower(response["decision"])
	reason := response["reason"]

	switch decision {
	case "allow":
		return SoftCheckResult{Allow: true, Reason: ""}, nil
	case "block":
		return SoftCheckResult{Allow: false, Reason: reason}, nil
	default:
		return SoftCheckResult{}, errors.New("unexpected decision: " + decision)
	}
}
