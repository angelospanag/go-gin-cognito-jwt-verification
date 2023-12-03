package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/angelospanag/go-gin-cognito-jwt-verification/middlewares"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func GetJWKS(awsRegion string, cognitoUserPoolId string) (*keyfunc.JWKS, error) {

	jwksURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", awsRegion, cognitoUserPoolId)

	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{})
	if err != nil {
		return nil, err
	}
	return jwks, nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	awsDefaultRegion := os.Getenv("AWS_DEFAULT_REGION")
	cognitoUserPoolId := os.Getenv("COGNITO_USER_POOL_ID")
	cognitoAppClientId := os.Getenv("COGNITO_APP_CLIENT_ID")

	jwks, err := GetJWKS(awsDefaultRegion, cognitoUserPoolId)

	if err != nil {
		log.Fatalf("Failed to retrieve Cognito JWKS\nError: %s", err)
	}

	router := gin.Default()

	router.GET("/healthcheck", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	router.GET("/protected-with-id-token", middlewares.CognitoAuthMiddleware(
		"id",
		awsDefaultRegion,
		cognitoUserPoolId,
		cognitoAppClientId,
		jwks), func(c *gin.Context) {
		username, _ := c.Get("username")
		c.JSON(http.StatusOK, gin.H{"username": username})
	})

	router.GET("/protected-with-access-token", middlewares.CognitoAuthMiddleware(
		"access",
		awsDefaultRegion,
		cognitoUserPoolId,
		cognitoAppClientId,
		jwks), func(c *gin.Context) {
		username, _ := c.Get("username")
		c.JSON(http.StatusOK, gin.H{"username": username})
	})
	router.Run()
}
