package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Key struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
	ExpiresAt  time.Time
}

var validKey Key
var expiredKey Key

func generateKey(expired bool) Key {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := uuid.New().String()

	expiry := time.Now().Add(1 * time.Hour)
	if expired {
		expiry = time.Now().Add(-1 * time.Hour)
	}

	return Key{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Kid:        kid,
		ExpiresAt:  expiry,
	}
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if time.Now().After(validKey.ExpiresAt) {
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
		return
	}

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": validKey.Kid,
		"use": "sig",
		"alg": "RS256",
		"n":   validKey.PublicKey.N.Text(16),
		"e":   big.NewInt(int64(validKey.PublicKey.E)).Text(16),
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []interface{}{jwk},
	})
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	useExpired := r.URL.Query().Get("expired") != ""

	key := validKey
	if useExpired {
		key = expiredKey
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "fakeUser",
		"exp": key.ExpiresAt.Unix(),
	})

	token.Header["kid"] = key.Kid

	signed, _ := token.SignedString(key.PrivateKey)
	w.Write([]byte(signed))
}

func main() {
	validKey = generateKey(false)
	expiredKey = generateKey(true)

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
