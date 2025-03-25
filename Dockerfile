# Stage 1: Build statically for Linux
FROM golang:1.21 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# ✅ Static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o coraza-proxy .

# Stage 2: Minimal runtime
FROM debian:bullseye-slim

WORKDIR /app

COPY --from=builder /app/coraza-proxy .
COPY rules.conf .

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

EXPOSE 8090
CMD ["./coraza-proxy"]
