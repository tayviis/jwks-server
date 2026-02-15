# Tayvis Sanders JWKS Server Project

## Overview
This project implements a JWKS server in Go.

What does it do?:
- Generates RSA key pairs
- Assigns unique `kid` values
- Implements key expiry
- Serves a JWKS endpoint
- Issues JWTs via `/auth`
- Supports expired JWTs using `?expired=true`

## Endpoints

### GET /.well-known/jwks.json
Returns the active public key in JWKS format.

### POST /auth
Returns a signed JWT.

Optional query parameter:
- `?expired=true` → issues JWT signed with expired key.

## Running the Server

go run main.go

## Running Tests

go test -cover

Current test coverage: 80.6%