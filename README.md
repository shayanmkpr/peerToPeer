# Peer-to-Peer Communication Server

A Go WebSocket server for real-time communication with monitoring and security features.

## 📁 Project Structure

```
peerTopeer/
├── cmd/server/main.go       # Main server (WebSocket + health endpoints)
├── http/middleman.go        # Monitoring & security middleware
├── internal/chat/           # Chat logic (empty - ready for your code)
└── go.mod                   # Dependencies
```

## 🚀 Quick Start

```bash
# Run the server
go run cmd/server/main.go

# Server starts on :8080
# WebSocket: ws://localhost:8080/ws
# Health: POST http://localhost:8080/health
```

## 🔧 What Each File Does

### `cmd/server/main.go` - Main Server
- **WebSocket handler** (`/ws`): Real-time communication
- **Health endpoint** (`/health`): Server status check
- **Connection management**: 60s timeout, 30s ping/pong
- **Message processing**: Echo server with JSON responses

### `http/middleman.go` - Monitoring Middleware
- **TrafficMonitor**: Logs all requests/responses with timing
- **SecurityMonitor**: Detects suspicious patterns (XSS, SQL injection, etc.)
- **PerformanceMonitor**: Tracks slow endpoints
- **RateLimitMonitor**: Basic rate limiting by IP

## 🛠️ Making Changes

### Add New Endpoints
Edit `cmd/server/main.go`:
```go
func newHandler(w http.ResponseWriter, r *http.Request) {
    // Your handler logic
}

func main() {
    http.HandleFunc("/your-endpoint", newHandler)
    // ... existing code
}
```

### Add Middleware
Edit `cmd/server/main.go` to wrap handlers:
```go
http.HandleFunc("/ws", TrafficMonitor(SecurityMonitor(wsHandler)))
```

### Add Chat Logic
Create files in `internal/chat/`:
- `room.go` - Chat room management
- `message.go` - Message handling
- `user.go` - User management

### Modify WebSocket Behavior
In `cmd/server/main.go`, update the `wsHandler` function:
- Change timeout: `conn.SetReadDeadline(time.Now().Add(60 * time.Second))`
- Modify ping interval: `ticker := time.NewTicker(30 * time.Second)`
- Add message routing logic in the reader goroutine

## 📡 Current Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ws` | WebSocket | Real-time communication |
| `/health` | POST | Server health check |

## 🔍 Development Tips

### Testing WebSocket
```javascript
const ws = new WebSocket('ws://localhost:8080/ws');
ws.onmessage = (event) => console.log('Received:', event.data);
ws.send('Hello!');
```

### Testing Health
```bash
curl -X POST http://localhost:8080/health
```

### Viewing Logs
The server logs all traffic, security alerts, and performance issues:
```
>>> [INCOMING] GET /ws from 127.0.0.1:12345
<<< [OUTGOING] GET /ws - Status: 101 - Duration: 2ms
⚠️  [SECURITY ALERT] Suspicious pattern detected
```

## 🎯 Next Steps

1. **Add chat rooms** in `internal/chat/`
2. **Implement user authentication**
3. **Add message persistence**
4. **Create frontend client**

## 📦 Dependencies

- Go 1.24.3+
- `github.com/gorilla/websocket v1.5.3`
