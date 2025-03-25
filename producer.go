// producer.go
package main

import (
	"encoding/json"
	"log"
	"time"

	"github.com/Shopify/sarama"
)

var producer sarama.SyncProducer

func initProducer(brokers []string) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 3

	var err error
	producer, err = sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.Fatalf("Failed to start Kafka producer: %v", err)
	}
	log.Println("[Kafka] Producer initialized")
}

type WAFEvent struct {
	Timestamp     time.Time   `json:"timestamp"`
	ClientIP      string      `json:"client_ip"`
	Method        string      `json:"method"`
	URI           string      `json:"uri"`
	UserAgent     string      `json:"user_agent"`
	StatusCode    int         `json:"status_code"`
	Action        string      `json:"action"` // "allowed" or "blocked"
	RuleTriggered *RuleDetail `json:"rule_triggered,omitempty"`
}

type RuleDetail struct {
	ID  string `json:"id"`
	Msg string `json:"msg"`
}

func publishWAFEvent(event WAFEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		log.Println("Failed to serialize WAF event:", err)
		return
	}

	msg := &sarama.ProducerMessage{
		Topic: "waf-traffic-events",
		Value: sarama.ByteEncoder(payload),
	}

	_, _, err = producer.SendMessage(msg)
	if err != nil {
		log.Println("Failed to send message to Kafka:", err)
	}
}
