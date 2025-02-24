package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
)

// Configuration for Pusher-like authentication
const (
	AppID     = "your_app_id"
	AppKey    = "your_app_key"
	AppSecret = "your_app_secret"
)

// ChannelManager manages subscriptions and broadcasts
type ChannelManager struct {
	channels      map[string][]*websocket.Conn            // Channel to list of connections
	subscriptions map[*websocket.Conn]map[string]struct{} // Connection to set of subscribed channels
	mu            sync.RWMutex                            // For thread safety
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

// Subscribe adds a connection to a channel
func (cm *ChannelManager) Subscribe(channel string, conn *websocket.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if _, ok := cm.channels[channel]; !ok {
		cm.channels[channel] = []*websocket.Conn{}
	}
	// Prevent duplicate subscriptions
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

// Unsubscribe removes a connection from a channel
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

// UnsubscribeAll removes a connection from all channels
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

// Broadcast sends a message to all connections in a channel
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

// AuthenticateTrigger checks the authentication for the /trigger endpoint
func AuthenticateTrigger(c *fiber.Ctx) error {
	authKey := c.Get("X-Pusher-Key")
	authSignature := c.Get("X-Pusher-Signature")
	body := string(c.Body())

	if authKey != AppKey {
		log.Printf("Authentication failed: Invalid app key %s", authKey)
		return c.Status(http.StatusUnauthorized).SendString("Unauthorized: Invalid app key")
	}

	mac := hmac.New(sha256.New, []byte(AppSecret))
	mac.Write([]byte(body))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	if authSignature != expectedSignature {
		log.Printf("Authentication failed: Invalid signature %s (expected %s)", authSignature, expectedSignature)
		return c.Status(http.StatusUnauthorized).SendString("Unauthorized: Invalid signature")
	}

	log.Printf("Trigger request authenticated successfully")
	return c.Next()
}

func main() {
	app := fiber.New()

	// Initialize logging
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Include timestamp and file info

	// WebSocket endpoint with Pusher protocol
	app.Get("/app/:key", websocket.New(func(c *websocket.Conn) {
		// Validate app key from URL parameter
		key := c.Params("key")
		if key != AppKey {
			log.Printf("Connection attempt with invalid app key: %s", key)
			c.Close()
			return
		}

		// Assign socket ID and log connection
		socketID := fmt.Sprintf("%p", c)
		log.Printf("Client %s connected with app key: %s", socketID, key)

		// Send connection established event (Pusher protocol)
		connData := map[string]interface{}{
			"event": "pusher:connection_established",
			"data": map[string]interface{}{
				"socket_id": socketID,
			},
		}
		connMsg, _ := json.Marshal(connData)
		if err := c.WriteMessage(websocket.TextMessage, connMsg); err != nil {
			log.Printf("Error sending connection established event to %s: %v", socketID, err)
			c.Close()
			return
		}

		// Cleanup when connection closes
		defer cm.UnsubscribeAll(c)

		for {
			mt, msg, err := c.ReadMessage()
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
								cm.Subscribe(channel, c)
							}
						}
					case "pusher:unsubscribe":
						if channelData, ok := data["data"].(map[string]interface{}); ok {
							if channel, ok := channelData["channel"].(string); ok {
								cm.Unsubscribe(channel, c)
							}
						}
					default:
						log.Printf("Client %s sent unhandled event: %s", socketID, event)
					}
				}
			}
		}
	}))

	// HTTP endpoint to trigger events with authentication
	app.Post("/trigger", AuthenticateTrigger, func(c *fiber.Ctx) error {
		var req TriggerRequest
		if err := c.BodyParser(&req); err != nil {
			log.Printf("Invalid trigger request: %v", err)
			return c.Status(http.StatusBadRequest).SendString("Invalid request")
		}
		eventData, err := json.Marshal(map[string]interface{}{
			"event":   req.Event,
			"channel": req.Channel,
			"data":    req.Data,
		})
		if err != nil {
			log.Printf("Error marshaling event for channel %s: %v", req.Channel, err)
			return c.Status(http.StatusInternalServerError).SendString("Error marshaling event")
		}
		cm.Broadcast(req.Channel, eventData)
		return c.SendString("Event triggered")
	})

	// Start the server
	log.Printf("Server starting on :3000")
	app.Listen("127.0.0.1:3000")
}
