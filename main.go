package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"
)

// Config file structure
type Config struct {
	Server struct {
		Port string `yaml:"port"`
	} `yaml:"server"`
	Cloudflare struct {
		CertsURL string `yaml:"certs_url"`
	} `yaml:"cloudflare"`
}

// Cloudflare JWT certificate response structure
type CloudflareCertsResponse struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		E   string `json:"e"`
		N   string `json:"n"`
	} `json:"keys"`
	PublicCert struct {
		Kid  string `json:"kid"`
		Cert string `json:"cert"`
	} `json:"public_cert"`
	PublicCerts []struct {
		Kid  string `json:"kid"`
		Cert string `json:"cert"`
	} `json:"public_certs"`
}

// JWT payload structure
type CloudflareAccessJWT struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
}

// Application structure
type App struct {
	Router    *mux.Router
	Templates *template.Template
	PublicKey *rsa.PublicKey
	Config    *Config
}

// Load YAML configuration file
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}

	file, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	err = yaml.Unmarshal(file, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}

	return config, nil
}

// Initialize application
func NewApp() (*App, error) {
	// Load configuration
	config, err := LoadConfig("config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	// Initialize router
	router := mux.NewRouter()

	// Load templates
	templates := template.Must(template.ParseGlob("templates/*.html"))

	// Get Cloudflare JWT verification public key
	var publicKey *rsa.PublicKey = nil

	// Get JWT verification certificate from Cloudflare certs endpoint
	if config.Cloudflare.CertsURL != "" {
		log.Printf("Fetching Cloudflare certificate: %s", config.Cloudflare.CertsURL)
		publicKey = fetchCloudflarePublicKey(config.Cloudflare.CertsURL)
	}

	app := &App{
		Router:    router,
		Templates: templates,
		PublicKey: publicKey,
		Config:    config,
	}

	// Set up routes
	app.routes()

	return app, nil
}

// Fetch Cloudflare public key
func fetchCloudflarePublicKey(certsURL string) *rsa.PublicKey {
	// Get JWT verification certificate from endpoint
	resp, err := http.Get(certsURL)
	if err != nil {
		log.Printf("Warning: Failed to fetch Cloudflare certificate: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Warning: Failed to fetch Cloudflare certificate: status code %d", resp.StatusCode)
		return nil
	}

	var certsResponse CloudflareCertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&certsResponse); err != nil {
		log.Printf("Warning: Failed to decode certificate response: %v", err)
		return nil
	}

	// Get certificate
	certPEM := certsResponse.PublicCert.Cert
	if certPEM == "" {
		log.Printf("Warning: Certificate is empty")
		return nil
	}

	log.Printf("Cloudflare certificate obtained (KID: %s)", certsResponse.PublicCert.Kid)

	// Parse x509 certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		log.Printf("Warning: Failed to decode PEM")
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Warning: Failed to parse certificate: %v", err)
		return nil
	}

	// Get public key
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Printf("Warning: Failed to get public key from certificate")
		return nil
	}

	log.Printf("Successfully obtained Cloudflare Access public key")
	return publicKey
}

// Route setup
func (app *App) routes() {
	// Page handlers
	app.Router.HandleFunc("/", app.indexHandler).Methods("GET")

	// Apply middleware
	app.Router.Use(app.loggingMiddleware)
}

// Logging middleware
func (app *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

// Index page handler
func (app *App) indexHandler(w http.ResponseWriter, r *http.Request) {
	// Data to pass to the template
	data := map[string]interface{}{}

	// Get token from cookie
	cookie, err := r.Cookie("CF_Authorization")

	// If cookie doesn't exist
	if err != nil {
		app.Templates.ExecuteTemplate(w, "index.html", data)
		return
	}

	// Decode JWT
	emailAddress, expiryTime, err := app.decodeJWT(cookie.Value)

	// If decoding fails
	if err != nil {
		log.Printf("JWT decode error: %v", err)
		app.Templates.ExecuteTemplate(w, "index.html", data)
		return
	}

	// Set data for successful decode
	data["Email"] = emailAddress
	data["ExpiresAt"] = expiryTime

	// Set session warning (if expiry is within 5 minutes)
	if expiryTime != nil && time.Until(expiryTime.Time) < 5*time.Minute {
		data["SessionWarning"] = true
	}

	// Render template
	app.Templates.ExecuteTemplate(w, "index.html", data)
}

// JWT decode function
func (app *App) decodeJWT(tokenString string) (string, *jwt.NumericDate, error) {
	// Remove Bearer prefix if present
	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	}

	// Parse JWT
	claims := &CloudflareAccessJWT{}

	// Key function
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Verify with public key if available
		if app.PublicKey != nil {
			return app.PublicKey, nil
		}
		// Skip verification if no public key
		log.Printf("Warning: No public key available, skipping signature verification")
		return jwt.UnsafeAllowNoneSignatureType, nil
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)

	// Parse error or invalid token
	if err != nil || !token.Valid {
		return "", nil, fmt.Errorf("invalid token: %v", err)
	}

	// Check for expired token
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return "", nil, fmt.Errorf("token expired")
	}

	// Check for email address
	if claims.Email == "" {
		return "", nil, fmt.Errorf("token does not contain an email address")
	}

	return claims.Email, claims.ExpiresAt, nil
}

func main() {
	app, err := NewApp()
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Server configuration
	port := app.Config.Server.Port
	if port == "" {
		port = "8080" // Default port
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      app.Router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	log.Printf("Server started: http://localhost:%s", port)
	log.Fatal(server.ListenAndServe())
}
