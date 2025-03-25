# Runtime Rule-Set Update WAF with REST API and Traffic Logging

## Overview
This project implements a production-ready, containerized Web Application Firewall (WAF) reverse proxy using **Coraza**, with the following key features:

- ✅ Real-time request inspection via [Coraza WAF](https://github.com/corazawaf/coraza)
- ✅ Runtime rule management via REST API (`/upsert-rule`, `/rule/:id`, `/rules`)
- ✅ Reverse proxy to a backend application (e.g., Nginx)
- ✅ Kafka-based traffic event streaming (blocked + allowed requests)
- ✅ Dockerized architecture for reproducibility and ease of deployment

---

## Project Name
**Runtime Rule-Set Update WAF (REST + Kafka)**

---

## Features

### 🔐 WAF Protection
- Uses [Coraza WAF](https://github.com/corazawaf/coraza) to inspect all HTTP traffic.
- Processes URI, method, headers, and optionally bodies.
- Detects and blocks malicious requests using ModSecurity-like rule syntax.

### 🔄 Dynamic Rule Updates (REST API)
- `POST /upsert-rule`: Add or update a rule by its ID
- `GET /rules`: List all rule IDs currently loaded
- `DELETE /rule/:id`: Remove a rule by ID
- Rule file (`rules.conf`) is reloaded at runtime via `fsnotify`

### 🔁 Traffic Logging to Kafka
- Logs every request (blocked or allowed) to a Kafka topic `waf-traffic-events`
- Kafka messages contain timestamp, client IP, URI, method, action, status code, and optional matched rule

---

## Project Structure

```
.
├── Dockerfile
├── docker-compose.yml
├── go.mod / go.sum
├── main.go               # Entry point and server setup
├── producer.go           # Kafka producer logic
├── rules.conf            # ModSecurity-style rule definitions
└── nginx/
    ├── default.conf      # Nginx backend config
    └── html/
        └── index.html
```

---

## REST API Endpoints

### `POST /upsert-rule`
- Accepts a single ModSecurity-style rule as raw text
- Parses and validates the rule syntax
- If rule with same ID exists: replaces it
- If new rule: appends it
- Example:

```bash
curl -X POST http://localhost:8090/upsert-rule \
  --data 'SecRule REQUEST_URI "@contains /admin" "id:1001,phase:1,deny,status:403,msg:\'Block admin access\'"'
```

### `GET /rules`
- Returns a JSON array of all rule IDs

### `DELETE /rule/:id`
- Deletes rule with the given ID from `rules.conf`

---

## Kafka Integration

- Uses the `sarama` Go client
- Topic: `waf-traffic-events`
- Each message is JSON-formatted:

```json
{
  "timestamp": "2025-03-25T10:27:00Z",
  "client_ip": "172.18.0.1",
  "method": "GET",
  "uri": "/login",
  "user_agent": "curl/8.1.2",
  "status_code": 403,
  "action": "blocked",
  "rule_triggered": {
    "id": "1001",
    "msg": "Block admin access"
  }
}
```

---

## How to Run

### 1. Build & Start All Services
```bash
docker-compose up --build
```

### 2. Test Proxy Functionality
```bash
curl http://localhost:8090/           # Allowed
curl http://localhost:8090/admin      # May be blocked by WAF rule
```

### 3. View Kafka Logs
```bash
docker exec -it kafka bash
kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic waf-traffic-events \
  --from-beginning
```

---

## Environment Variables

| Variable                 | Description                     |
|--------------------------|----------------------------------|
| `BACKEND_URL`            | Backend server to proxy to      |

---

## Tech Stack
- Go 1.21
- Coraza v3
- Kafka 3.6 (Bitnami image)
- Docker Compose v3.8
- Zookeeper 3.8

---

## Future Improvements
- Add authentication on rule API endpoints
- Implement rule validation preview endpoint
- Build a UI to manage rule set and view traffic in real time
- Push logs to Elasticsearch for dashboarding

---

