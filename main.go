package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleOauthConfig *oauth2.Config
var oauthStateString = "random"

// Initialize Google OAuth2 config
func init() {
	b, err := ioutil.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	googleOauthConfig, err = google.ConfigFromJSON(b, "https://www.googleapis.com/auth/userinfo.email")
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
}

func main() {
	router := gin.Default()

	router.GET("/login", handleGoogleLogin)
	router.GET("/callback", handleGoogleCallback)
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
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
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
	userInfo, err := ioutil.ReadAll(response.Body)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to read user info"})
		return
	}

	var user map[string]interface{}
	if err := json.Unmarshal(userInfo, &user); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to parse user info"})
		return
	}

	// Store user info in a secure cookie or session (for simplicity, we use a cookie here)
	c.SetCookie("user", string(userInfo), 3600, "/", "localhost", false, true)
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

		var user map[string]interface{}
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
