package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	gokiteconnect "github.com/zerodhatech/gokiteconnect"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var rateLimiter = rate.NewLimiter(5, 50) 

type User struct {
	ZerodhaUsername string `gorm:"primaryKey"`
	AccessToken     string
	PublicToken     string
	RefreshToken    string
	IsPublic        bool
	LastLogin       time.Time
}

func main() {
	var err error

	dsn := "user=admin password=admin@123 dbname=retardDB sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&User{})

	router := mux.NewRouter()

	router.HandleFunc("/login", loginHandler).Methods("GET")
	router.HandleFunc("/callback", callbackHandler).Methods("GET")
	router.HandleFunc("/portfolio/{username}", portfolioHandler).Methods("GET")
	router.HandleFunc("/toggle-visibility/{username}", toggleVisibilityHandler).Methods("POST")

	log.Println("Server running on port 8080")
	http.ListenAndServe(":8080", rateLimit(router))
}

func rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rateLimiter.Allow() {
			http.Error(w, "Too many requests. Try again later.", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := os.Getenv("ZERODHA_API_KEY")
	redirectURI := "http://localhost:8080/callback"
	loginURL := fmt.Sprintf("https://kite.zerodha.com/connect/login?v=3&api_key=%s&redirect_uri=%s", apiKey, redirectURI)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	requestToken := r.URL.Query().Get("request_token")
	if requestToken == "" {
		http.Error(w, "Request token missing", http.StatusBadRequest)
		return
	}

	apiKey := os.Getenv("ZERODHA_API_KEY")
	apiSecret := os.Getenv("ZERODHA_API_SECRET")

	kite := gokiteconnect.New(apiKey)

	user, err := kite.GenerateSession(requestToken, apiSecret)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	userRecord := User{
		ZerodhaUsername: user.UserName,
		AccessToken:     user.AccessToken,
		PublicToken:     user.PublicToken,
		RefreshToken:    user.RefreshToken,
		LastLogin:       time.Now(),
	}


	result := db.Save(&userRecord)
	if result.Error != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	portfolioURL := fmt.Sprintf("/portfolio/%s", user.UserName)
	http.Redirect(w, r, portfolioURL, http.StatusTemporaryRedirect)
}

func portfolioHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	var user User
	result := db.First(&user, "zerodha_username = ?", username)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if !user.IsPublic {
		http.Error(w, "Portfolio is private", http.StatusForbidden)
		return
	}


	kite := gokiteconnect.New(os.Getenv("ZERODHA_API_KEY"))
	_, err := kite.GetUserProfile()
	if err != nil {

		newAccessToken, err := refreshAccessToken(user.RefreshToken)
		if err != nil {
			http.Error(w, "Failed to refresh access token", http.StatusInternalServerError)
			return
		}


		user.AccessToken = newAccessToken
		result = db.Save(&user)
		if result.Error != nil {
			http.Error(w, "Failed to update access token", http.StatusInternalServerError)
			return
		}


		kite.SetAccessToken(newAccessToken)
	} else {
		kite.SetAccessToken(user.AccessToken)
	}


	portfolioData, err := kite.GetHoldings()
	if err != nil {
		http.Error(w, "Failed to fetch portfolio", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(portfolioData)
}

func toggleVisibilityHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	var user User
	result := db.First(&user, "zerodha_username = ?", username)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}


	user.IsPublic = !user.IsPublic
	result = db.Save(&user)
	if result.Error != nil {
		http.Error(w, "Failed to update visibility", http.StatusInternalServerError)
		return
	}


	response := struct {
		Message string `json:"message"`
	}{
		Message: "Portfolio visibility updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func refreshAccessToken(refreshToken string) (string, error) {
	apiKey := os.Getenv("ZERODHA_API_KEY")
	apiSecret := os.Getenv("ZERODHA_API_SECRET")

	kite := gokiteconnect.New(apiKey)
	accessToken, err := kite.RenewAccessToken(refreshToken, apiSecret)
	if err != nil {
		return "", err
	}
	return accessToken.AccessToken, nil
}
