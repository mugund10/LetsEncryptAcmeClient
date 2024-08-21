package challenges

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
)

// handleHTTPChallenge starts a temporary HTTP server to respond to the HTTP-01 challenge.
func HandleHTTPChallenge(clie *acme.Client, ctx context.Context, chall *acme.Challenge) error {

	keyAuth, err := clie.HTTP01ChallengeResponse(chall.Token)
	if err != nil {
		return fmt.Errorf("failed to generate key authorization: %v", err)
	}

	// Start a temporary HTTP server
	srv := &http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			challengePath := "/.well-known/acme-challenge/" + chall.Token
			if r.URL.Path == challengePath {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(keyAuth))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()
	fmt.Println("Temporary HTTP server started, serving the challenge.")

	// Accept the challenge
	_, err = clie.Accept(ctx, chall)
	if err != nil {
		return fmt.Errorf("failed to accept HTTP-01 challenge: %v", err)
	}

	// Wait for authorization to complete
	auth, err := clie.WaitAuthorization(ctx, chall.URI)
	if err != nil {
		return fmt.Errorf("failed to wait for authorization: %v", err)
	}

	if auth.Status == acme.StatusValid {
		fmt.Println("Authorization completed successfully.")
	} else {
		return fmt.Errorf("authorization failed with status: %s", auth.Status)
	}

	// Shutdown the temporary server
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shut down HTTP server: %v", err)
	}
	fmt.Println("Temporary HTTP server stopped.")

	return nil
}
