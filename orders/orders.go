package orders

import (
	"context"
	"fmt"
	"log"

	"github.com/mugund10/LetsEncryptAcmeClient/challenges"
	"golang.org/x/crypto/acme"
)

func MakeOrder(ctx context.Context, cli *acme.Client, domain []acme.AuthzID) {
	order, err := cli.AuthorizeOrder(ctx, domain)
	if err != nil {
		log.Fatalf("failed to authorize order : %v", err)
	}

	for _, authurl := range order.AuthzURLs {
		auth, err := cli.GetAuthorization(ctx, authurl)
		if err != nil {
			log.Fatalf("failed to get authorization: %v", err)
		}

		for _, challenge := range auth.Challenges {
			if challenge.Type == "http-01" {
				fmt.Printf("Handling HTTP-01 challenge: %+v\n", challenge)

				// Handle the HTTP-01 challenge
				err := challenges.HandleHTTPChallenge(cli, ctx, challenge)
				if err != nil {
					log.Fatalf("Failed to handle HTTP-01 challenge: %v", err)
				}

				// Wait for the entire authorization to complete
				auth, err = cli.WaitAuthorization(ctx, auth.URI)
				if err != nil {
					log.Fatalf("Failed to wait for authorization: %v", err)
				}

				// Check the status of the authorization and its challenges
				if auth.Status == acme.StatusValid {
					fmt.Printf("Authorization completed successfully: %+v\n", auth)
				} else {
					fmt.Printf("Authorization failed or is still pending: %+v\n", auth)
				}
				break
			}
		}
		fmt.Printf("status Authorization: %+v\n", auth)

		fmt.Printf("last: %+v\n", order)

	}
}
