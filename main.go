package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// In production check origin properly:
	CheckOrigin: func(r *http.Request) bool { return true },
}

func roomHealthHandler(w http.ResponseWriter, r *http.Request) {
	// check if a room is live or not
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]string{"status": "ok"}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer conn.Close()

	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Reader goroutine
	go func() {
		for {
			mt, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				conn.Close()
				return
			}
			// process message (e.g., route by JSON type)
			log.Printf("recv: %s", message)
			log.Println(mt)
			// simple echo
			if err := conn.WriteMessage(mt, message); err != nil {
				log.Println("write:", err)
				return
			}

			data := map[string]interface{}{
				"dummy": "John Doe",
			}
			dummy, _ := json.Marshal(data)

			if err := conn.WriteMessage(1, dummy); err != nil {
				log.Println("write:", err)
				return
			}
		}
	}()

	// Simple ping ticker
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			log.Println("ping failed:", err)
			return
		}
	}
}

func main() {
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/health", roomHealthHandler)
	log.Println("Hello. I am listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
