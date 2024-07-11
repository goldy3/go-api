package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestGoogleCallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Set environment to test
	os.Setenv("GO_ENV", "test")

	// Initialize the database connection for testing
	initializeDatabase()
	initializeOAuthConfig()

	// Create a test HTTP server
	router := gin.Default()
	router.GET("/google/callback", handleGoogleCallback)

	// Mock Google user info response
	googleUser := User{
		ID:       "12345",
		Email:    "testuser@gmail.com",
		FullName: "Test User",
	}
	userInfo, _ := json.Marshal(googleUser)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(userInfo)
	}))
	defer ts.Close()

	// Mock Google OAuth2 token exchange
	googleOauthConfig.Endpoint.TokenURL = ts.URL

	// Simulate a callback request
	req, _ := http.NewRequest(http.MethodGet, "/google/callback?state=random&code=authcode", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check if the user was saved in the test database
	var savedUser User
	db.Where("id = ?", googleUser.ID).First(&savedUser)
	assert.Equal(t, googleUser.Email, savedUser.Email)
	assert.Equal(t, googleUser.FullName, savedUser.FullName)
}
