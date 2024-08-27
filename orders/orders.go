package orders

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/mugund10/LetsEncryptAcmeClient/Account"
	"github.com/mugund10/LetsEncryptAcmeClient/challenges"
	"github.com/mugund10/LetsEncryptAcmeClient/errs"
	"github.com/mugund10/LetsEncryptAcmeClient/keys"
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

// submits an order for a certificates
func (om *orderMan) Create(ctx context.Context, client *acme.Client) {
	order, err := client.AuthorizeOrder(ctx, om.domain)
	if err != nil {
		log.Fatalf("failed to authorize order : %v", err)
	} //after sends order the acme server need to verify the
	for _, authurl := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authurl)
		if err != nil {
			log.Fatalf("failed to get authorization: %v", err)
		} // challenges are for to prove the control over domain
		for _, challenge := range auth.Challenges {
			// "http-01" only implemented
			if challenge.Type == "http-01" {
				// fmt.Printf("Handling HTTP-01 challenge: %+v\n", challenge)
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

func (om *orderMan) Finish(cli *acme.Client) {
	//key implementation for csr
	dom := om.domain[0].Value
	cert := Account.NewCert(dom)
	var certurl string
	kname := fmt.Sprintf("pk[%s]", dom)
	key := keys.New(kname)
	err := key.RsaGen()
	errs.CheckError(err)
	readsRsa := key.LoadPem()
	if readsRsa != nil {
		fmt.Println("key not found locally, so saving newly generated key")
		saves := key.SaveAsPem()
		errs.CheckError(saves)
	}
	// generate csr
	csr, err := key.CsrGen([]string{dom})
	errs.CheckError(err)
	readscsr := csr.LoadPem()
	if readscsr != nil {
		fmt.Println("Csr not found locally, so saving newly generated Csr")
		saves := csr.SaveAsPem()
		errs.CheckError(saves)
		_, certurl, err = cli.CreateOrderCert(context.Background(), om.order.FinalizeURL, csr.Bytes, true)
		errs.CheckError(err)
		//saves certificate url as json
		cert.Save(certurl)
		fmt.Println("[if]certurl:", certurl)
		fmt.Printf("last: %+v\n", om.order)
	} else {
		cert.Load()
		certurl = cert.Url
		fmt.Println("[else]certurl:", certurl)
		fmt.Printf("last: %+v\n", om.order)

	}
	finalcert, err := cli.FetchCert(context.Background(), certurl, true)
	errs.CheckError(err)
	//fmt.Println(finalcert)

	for i, certBytes := range finalcert {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			fmt.Println("Error parsing certificate:", err)
			return
		}
		filename := fmt.Sprintf("certificate_%d.pem", i)
		err = saveCertificateToFile(filename, cert)
		if err != nil {
			fmt.Println("Error saving certificate:", err)
			return
		}
		fmt.Printf("Certificate %d saved successfully to %s\n", i, filename)
	}
	fullchain()
}

func saveCertificateToFile(filename string, cert *x509.Certificate) error {
	// Encode the certificate to PEM format
	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	// Write the PEM encoded certificate to the file
	err := os.WriteFile(filename, certBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write certificate to file: %w", err)
	}
	return nil
}

func fullchain() {
	// Define the paths to the certificate files
	leafCertPath := "certificate_0.pem"
	intermediateCertPath := "certificate_1.pem"
	fullChainPath := "fullchain.pem"

	// Read the leaf certificate
	leafCert, err := os.ReadFile(leafCertPath)
	if err != nil {
		fmt.Printf("Error reading leaf certificate: %v\n", err)
		return
	}

	// Read the intermediate certificate
	intermediateCert, err := os.ReadFile(intermediateCertPath)
	if err != nil {
		fmt.Printf("Error reading intermediate certificate: %v\n", err)
		return
	}

	// Combine the certificates into a single PEM file
	fullChain := append(leafCert, intermediateCert...)

	// Write the combined certificates to a new file
	err = os.WriteFile(fullChainPath, fullChain, 0644)
	if err != nil {
		fmt.Printf("Error writing full chain file: %v\n", err)
		return
	}

	fmt.Printf("Full chain file created successfully at %s\n", filepath.Join(".", fullChainPath))
}
