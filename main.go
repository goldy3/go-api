package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Config struct {
	GoogleRedirectURL    string `json:"google_redirect_url"`
	MicrosoftRedirectURL string `json:"microsoft_redirect_url"`
	OtherConfig          string `json:"some_other_config"`
}

var googleOauthConfig *oauth2.Config
var microsoftOauthConfig *oauth2.Config
var oauthStateString = "random"
var db *gorm.DB

func initializeDatabase() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Use test database if running tests
	dsn := os.Getenv("DATABASE_URL")
	if os.Getenv("GO_ENV") == "test" {
		dsn = os.Getenv("TEST_DATABASE_URL")
	}

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	gormDB.AutoMigrate(&User{})

	db = gormDB
}

func initializeOAuthConfig() {
	// Load JSON configuration file
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Error opening config file: %v", err)
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)

	var config Config
	json.Unmarshal(byteValue, &config)

	// Google OAuth configuration
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  config.GoogleRedirectURL,
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	// Microsoft OAuth configuration
	microsoftOauthConfig = &oauth2.Config{
		RedirectURL:  config.MicrosoftRedirectURL,
		ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
		ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
		Scopes:       []string{"https://graph.microsoft.com/User.Read"},
		Endpoint:     microsoft.AzureADEndpoint("common"),
	}
}

func init() {
	initializeDatabase()
	initializeOAuthConfig()
}

type User struct {
	ID       string `gorm:"primaryKey"`
	Email    string `gorm:"unique"`
	FullName string
}

func main() {
	router := gin.Default()

	// Serve the login page using the template
	router.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.File("templates/index.html")
	})

	router.GET("/google/login", handleGoogleLogin)
	router.GET("/google/callback", handleGoogleCallback)
	router.GET("/microsoft/login", handleMicrosoftLogin)
	router.GET("/microsoft/callback", handleMicrosoftCallback)
	authorized := router.Group("/")
	authorized.Use(authMiddleware())
	{
		authorized.POST("/run-playbook", runPlaybook)
	}

	router.Run(":8080")
}

func handleGoogleLogin(c *gin.Context) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleGoogleCallback(c *gin.Context) {
	state := c.Query("state")
	if state != oauthStateString {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid state"})
		return
	}

	code := c.Query("code")
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "code exchange failed"})
		return
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to get user info"})
		return
	}
	defer response.Body.Close()
	userInfo, err := io.ReadAll(response.Body)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to read user info"})
		return
	}

	var googleUser struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		FullName string `json:"name"`
	}
	if err := json.Unmarshal(userInfo, &googleUser); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to parse user info"})
		return
	}

	// Save user info to the database
	user := User{
		ID:       googleUser.ID,
		Email:    googleUser.Email,
		FullName: googleUser.FullName,
	}
	if err := db.FirstOrCreate(&user, User{ID: googleUser.ID}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save user"})
		return
	}

	// Store user info in a secure cookie or session
	userJson, _ := json.Marshal(user)
	c.SetCookie("user", string(userJson), 3600, "/", "localhost", false, true)
	c.JSON(http.StatusOK, user)
}

func handleMicrosoftLogin(c *gin.Context) {
	url := microsoftOauthConfig.AuthCodeURL(oauthStateString)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleMicrosoftCallback(c *gin.Context) {
	state := c.Query("state")
	if state != oauthStateString {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid state"})
		return
	}

	code := c.Query("code")
	token, err := microsoftOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "code exchange failed"})
		return
	}

	response, err := http.Get("https://graph.microsoft.com/v1.0/me?access_token=" + token.AccessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to get user info"})
		return
	}
	defer response.Body.Close()
	userInfo, err := io.ReadAll(response.Body)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to read user info"})
		return
	}

	var microsoftUser struct {
		ID       string `json:"id"`
		Email    string `json:"userPrincipalName"`
		FullName string `json:"displayName"`
	}
	if err := json.Unmarshal(userInfo, &microsoftUser); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to parse user info"})
		return
	}

	// Save user info to the database
	user := User{
		ID:       microsoftUser.ID,
		Email:    microsoftUser.Email,
		FullName: microsoftUser.FullName,
	}
	if err := db.FirstOrCreate(&user, User{ID: microsoftUser.ID}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save user"})
		return
	}

	// Store user info in a secure cookie or session
	userJson, _ := json.Marshal(user)
	c.SetCookie("user", string(userJson), 3600, "/", "localhost", false, true)
	c.JSON(http.StatusOK, user)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("user")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		var user User
		if err := json.Unmarshal([]byte(cookie), &user); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

func runPlaybook(c *gin.Context) {
	var request struct {
		Playbook  string `json:"playbook"`
		Inventory string `json:"inventory"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cmd := exec.Command("ansible-playbook", "-i", request.Inventory, request.Playbook)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error executing playbook: %v\nOutput: %s", err, string(output))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "output": string(output)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"output": string(output)})
}
