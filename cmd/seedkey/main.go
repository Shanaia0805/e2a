// seedkey is a one-shot dev helper: creates a user + account-scoped API key
// and prints the plaintext key to stdout.
//
// Usage:
//
//	go run ./cmd/seedkey
//
// The DATABASE_URL can be overridden via E2A_DATABASE_URL env var.
// Defaults to the standard docker-compose dev URL.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tokencanopy/e2a/internal/identity"
)

func main() {
	dbURL := os.Getenv("E2A_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://e2a:e2a@localhost:5433/e2a?sslmode=disable"
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	store := identity.NewStore(pool)

	// Create (or reuse) a dev user.
	user, err := store.CreateOrGetUser(ctx, "dev@local.test", "Dev User", "google-dev-local")
	if err != nil {
		log.Fatalf("CreateOrGetUser: %v", err)
	}
	fmt.Printf("User: %s  (id=%s)\n", user.Email, user.ID)

	// Mint a fresh account-scoped API key.
	key, err := store.CreateAPIKey(ctx, user.ID, "dev-seed-key", nil)
	if err != nil {
		log.Fatalf("CreateAPIKey: %v", err)
	}

	fmt.Println("─────────────────────────────────────────────────────")
	fmt.Printf("API Key (copy this, shown ONCE): %s\n", key.PlaintextKey)
	fmt.Println("─────────────────────────────────────────────────────")
	fmt.Println("Use it as:  Authorization: Bearer <key above>")
}
