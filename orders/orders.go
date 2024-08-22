package orders

import (
	"context"
	"fmt"
	"log"

	"github.com/mugund10/LetsEncryptAcmeClient/challenges"
	"golang.org/x/crypto/acme"
)

type orderMan struct {
	domain []acme.AuthzID
	order  *acme.Order
}

// adds the domain or subdomain for your order
func New(domainAddress string) orderMan {
	var om orderMan
	domain := []acme.AuthzID{{Type: "dns", Value: domainAddress}}
	om.domain = domain
	return om 
}

//submits an order for a certificates
func(om *orderMan) Make(ctx context.Context, client *acme.Client) {
	order, err := client.AuthorizeOrder(ctx, om.domain)
	if err != nil {
		log.Fatalf("failed to authorize order : %v", err)
	}//after sends order the acme server need to verify the
	for _, authurl := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authurl)
		if err != nil {
			log.Fatalf("failed to get authorization: %v", err)
		}// challenges are for to prove the control over domain 
		for _, challenge := range auth.Challenges {
			// "http-01" only implemented
			if challenge.Type == "http-01" {
				fmt.Printf("Handling HTTP-01 challenge: %+v\n", challenge)
				// Handles the HTTP-01 challenge
				err := challenges.HandleHTTPChallenge(client, ctx, challenge)
				if err != nil {
					log.Fatalf("Failed to handle HTTP-01 challenge: %v", err)
				}
				// Wait for the entire authorization to complete
				auth, err = client.WaitAuthorization(ctx, auth.URI)
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
		// fmt.Printf("status Authorization: %+v\n", auth)
		// fmt.Printf("last: %+v\n", order)
		om.order = order
	}
}
