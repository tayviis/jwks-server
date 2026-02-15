package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func setup() {
	validKey = generateKey(false)
	expiredKey = generateKey(true)
}

func TestJWKSHandler(t *testing.T) {
	setup()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	jwksHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestJWKSWrongMethod(t *testing.T) {
	setup()

	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	jwksHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestAuthValid(t *testing.T) {
	setup()

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthExpired(t *testing.T) {
	setup()

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthWrongMethod(t *testing.T) {
	setup()

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}
func TestJWKSWhenExpired(t *testing.T) {
	setup()

	// Force the valid key to be expired
	validKey = generateKey(true)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	jwksHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
