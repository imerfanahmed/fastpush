package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// Configuration for Pusher-like authentication
const (
	AppID     = "your_app_id"
	AppKey    = "your_app_key"
	AppSecret = "your_app_secret"
)

// ChannelManager manages subscriptions and broadcasts
type ChannelManager struct {
	channels      map[string][]*websocket.Conn
	subscriptions map[*websocket.Conn]map[string]struct{}
	mu            sync.RWMutex
}

// TriggerRequest defines the structure for the /trigger endpoint
type TriggerRequest struct {
	Channel string                 `json:"channel"`
	Event   string                 `json:"event"`
	Data    map[string]interface{} `json:"data"`
}

// Global instance of ChannelManager
var cm = ChannelManager{
	channels:      make(map[string][]*websocket.Conn),
	subscriptions: make(map[*websocket.Conn]map[string]struct{}),
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true }, // Adjust origin checking as needed
}

func (cm *ChannelManager) Subscribe(channel string, conn *websocket.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if _, ok := cm.channels[channel]; !ok {
		cm.channels[channel] = []*websocket.Conn{}
	}
	for _, c := range cm.channels[channel] {
		if c == conn {
			return
		}
	}
	cm.channels[channel] = append(cm.channels[channel], conn)
	if _, ok := cm.subscriptions[conn]; !ok {
		cm.subscriptions[conn] = make(map[string]struct{})
	}
	cm.subscriptions[conn][channel] = struct{}{}
	log.Printf("Client %p subscribed to channel: %s", conn, channel)
}

func (cm *ChannelManager) Unsubscribe(channel string, conn *websocket.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if conns, ok := cm.channels[channel]; ok {
		for i, c := range conns {
			if c == conn {
				cm.channels[channel] = append(conns[:i], conns[i+1:]...)
				break
			}
		}
		if len(cm.channels[channel]) == 0 {
			delete(cm.channels, channel)
		}
	}
	if subs, ok := cm.subscriptions[conn]; ok {
		delete(subs, channel)
		if len(subs) == 0 {
			delete(cm.subscriptions, conn)
		}
	}
	log.Printf("Client %p unsubscribed from channel: %s", conn, channel)
}

func (cm *ChannelManager) UnsubscribeAll(conn *websocket.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if subs, ok := cm.subscriptions[conn]; ok {
		for channel := range subs {
			if conns, ok := cm.channels[channel]; ok {
				for i, c := range conns {
					if c == conn {
						cm.channels[channel] = append(conns[:i], conns[i+1:]...)
						break
					}
				}
				if len(cm.channels[channel]) == 0 {
					delete(cm.channels, channel)
				}
			}
		}
		delete(cm.subscriptions, conn)
	}
	log.Printf("Client %p disconnected and unsubscribed from all channels", conn)
}

func (cm *ChannelManager) Broadcast(channel string, message []byte) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if conns, ok := cm.channels[channel]; ok {
		for _, conn := range conns {
			conn.WriteMessage(websocket.TextMessage, message)
		}
	}
	log.Printf("Broadcasted event to channel %s: %s", channel, string(message))
}

func AuthenticateTrigger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authKey := r.Header.Get("X-Pusher-Key")
		authSignature := r.Header.Get("X-Pusher-Signature")
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		if authKey != AppKey {
			log.Printf("Authentication failed: Invalid app key %s", authKey)
			http.Error(w, "Unauthorized: Invalid app key", http.StatusUnauthorized)
			return
		}

		mac := hmac.New(sha256.New, []byte(AppSecret))
		mac.Write(body)
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		if authSignature != expectedSignature {
			log.Printf("Authentication failed: Invalid signature %s (expected %s)", authSignature, expectedSignature)
			http.Error(w, "Unauthorized: Invalid signature", http.StatusUnauthorized)
			return
		}

		log.Printf("Trigger request authenticated successfully")
		next.ServeHTTP(w, r)
	})
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]
	
	if key != AppKey {
		log.Printf("Connection attempt with invalid app key: %s", key)
		http.Error(w, "Invalid app key", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	socketID := fmt.Sprintf("%p", conn)
	log.Printf("Client %s connected with app key: %s", socketID, key)

	connData := map[string]interface{}{
		"event": "pusher:connection_established",
		"data": map[string]interface{}{
			"socket_id": socketID,
		},
	}
	connMsg, _ := json.Marshal(connData)
	if err := conn.WriteMessage(websocket.TextMessage, connMsg); err != nil {
		log.Printf("Error sending connection established event to %s: %v", socketID, err)
		conn.Close()
		return
	}

	defer cm.UnsubscribeAll(conn)

	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Client %s read error: %v", socketID, err)
			break
		}
		if mt == websocket.TextMessage {
			var data map[string]interface{}
			if err := json.Unmarshal(msg, &data); err != nil {
				log.Printf("Client %s sent invalid JSON: %v", socketID, err)
				continue
			}
			if event, ok := data["event"].(string); ok {
				switch event {
				case "pusher:subscribe":
					if channelData, ok := data["data"].(map[string]interface{}); ok {
						if channel, ok := channelData["channel"].(string); ok {
							cm.Subscribe(channel, conn)
						}
					}
				case "pusher:unsubscribe":
					if channelData, ok := data["data"].(map[string]interface{}); ok {
						if channel, ok := channelData["channel"].(string); ok {
							cm.Unsubscribe(channel, conn)
						}
					}
				default:
					log.Printf("Client %s sent unhandled event: %s", socketID, event)
				}
			}
		}
	}
}

func triggerHandler(w http.ResponseWriter, r *http.Request) {
	var req TriggerRequest
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("Invalid trigger request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	eventData, err := json.Marshal(map[string]interface{}{
		"event":   req.Event,
		"channel": req.Channel,
		"data":    req.Data,
	})
	if err != nil {
		log.Printf("Error marshaling event for channel %s: %v", req.Channel, err)
		http.Error(w, "Error marshaling event", http.StatusInternalServerError)
		return
	}
	cm.Broadcast(req.Channel, eventData)
	fmt.Fprintf(w, "Event triggered")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	router := mux.NewRouter()
	
	// WebSocket endpoint
	router.HandleFunc("/app/{key}", websocketHandler).Methods("GET")
	
	// Trigger endpoint with authentication middleware
	router.Handle("/trigger", AuthenticateTrigger(http.HandlerFunc(triggerHandler))).Methods("POST")

	log.Printf("Server starting on :3000")
	if err := http.ListenAndServe("127.0.0.1:3000", router); err != nil {
		log.Fatal("Server failed to start: ", err)
	}
}