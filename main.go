package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql"
	"bytes"
)

// AppConfig represents an application configuration from the database
type AppConfig struct {
	AppID     string
	AppKey    string
	AppSecret string
}

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

// Global instance of ChannelManager and AppConfigs
var (
	cm        = ChannelManager{
		channels:      make(map[string][]*websocket.Conn),
		subscriptions: make(map[*websocket.Conn]map[string]struct{}),
	}
	appConfigs = make(map[string]AppConfig) // Map of appKey to AppConfig
)

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file: ", err)
	}
}

func loadAppConfigs(db *sql.DB) {
	rows, err := db.Query("SELECT id, `key`, secret FROM apps")
	if err != nil {
		log.Fatal("Error querying apps: ", err)
	}
	defer rows.Close()

	for rows.Next() {
		var config AppConfig
		if err := rows.Scan(&config.AppID, &config.AppKey, &config.AppSecret); err != nil {
			log.Fatal("Error scanning app config: ", err)
		}
		appConfigs[config.AppKey] = config
	}
	log.Printf("Loaded %d app configurations", len(appConfigs))
}

// ChannelManager methods (Subscribe, Unsubscribe, UnsubscribeAll, Broadcast) remain unchanged
// ... [Previous ChannelManager methods stay the same] ...

func AuthenticateTrigger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authKey := r.Header.Get("X-Pusher-Key")
		authSignature := r.Header.Get("X-Pusher-Signature")
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		config, ok := appConfigs[authKey]
		if !ok {
			log.Printf("Authentication failed: Invalid app key %s", authKey)
			http.Error(w, "Unauthorized: Invalid app key", http.StatusUnauthorized)
			return
		}

		mac := hmac.New(sha256.New, []byte(config.AppSecret))
		mac.Write(body)
		expectedSignature := hex.EncodeToString(mac.Sum(nil))

		if authSignature != expectedSignature {
			log.Printf("Authentication failed: Invalid signature %s (expected %s)", authSignature, expectedSignature)
			http.Error(w, "Unauthorized: Invalid signature", http.StatusUnauthorized)
			return
		}

		log.Printf("Trigger request authenticated successfully for app %s", config.AppID)
		r.Body = io.NopCloser(bytes.NewBuffer(body)) // Reset body for downstream handlers
		next.ServeHTTP(w, r)
	})
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	key := vars["key"]
	
	config, ok := appConfigs[key]
	if !ok {
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
	log.Printf("Client %s connected with app key: %s (app_id: %s)", socketID, key, config.AppID)

	// Rest of websocketHandler remains the same
	// ... [Previous websocketHandler code] ...
}

// triggerHandler remains unchanged
// ... [Previous triggerHandler code] ...

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Load environment variables
	loadEnv()

	// Database connection
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		os.Getenv("DB_USERNAME"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_DATABASE"),
	)
	
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}
	defer db.Close()

	// Load app configurations
	loadAppConfigs(db)

	router := mux.NewRouter()
	
	router.HandleFunc("/app/{key}", websocketHandler).Methods("GET")
	router.Handle("/trigger", AuthenticateTrigger(http.HandlerFunc(websocketHandler))).Methods("POST")
	serverHost := os.Getenv("HOST")
	serverPort := os.Getenv("PORT")
	log.Printf("Server starting on :%s", serverPort)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%s",serverHost, serverPort), router); err != nil {
		log.Fatal("Server failed to start: ", err)
	}
}