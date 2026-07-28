package middlewares_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/angelospanag/go-gin-cognito-jwt-verification/middlewares"
	"github.com/gin-gonic/gin"
)

func newTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/healthcheck", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	r.GET("/protected", middlewares.CognitoAuthMiddleware("id", "us-east-1", "pool", "client", nil), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func TestHealthcheck(t *testing.T) {
	r := newTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/healthcheck", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMiddleware_NoAuthHeader(t *testing.T) {
	r := newTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_MalformedAuthHeader(t *testing.T) {
	r := newTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "NotBearer sometoken")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestMiddleware_EmptyBearer(t *testing.T) {
	r := newTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer ")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
