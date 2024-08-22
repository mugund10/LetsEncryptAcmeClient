package leacme

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/mugund10/LetsEncryptAcmeClient/Account"
	"github.com/mugund10/LetsEncryptAcmeClient/orders"
	"golang.org/x/crypto/acme"
)

// endpoints
var (
	productionurl string = "https://acme-v02.api.letsencrypt.org/directory"
	stagingurl    string = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// default url is staging
var url *string

type client struct {
	acme_client *acme.Client
}

// creates new client with given private key
// for stagingUrl ("https://acme-staging-v02.api.letsencrypt.org/directory") value must be true
// if its false productionUrl will be used  productionurl string "https://acme-v02.api.letsencrypt.org/directory"
func NewClient(pkey *rsa.PrivateKey, stagingUrl bool) client {
	if stagingUrl {
		url = &stagingurl
	} else {
		url = &productionurl
	}
	var ca client
	client := acme.Client{Key: pkey, DirectoryURL: *url}
	ca.acme_client = &client
	return ca
}

// registers a new account with acme server or
// retrieves old registered account with the given private key
// ( for contactaddress use this "mailto:example@example.com" format )
func (ca *client) RegisterAccount(accountName string, contactaddress string) {
	//here account is variable name and Account is package name
	account := Account.New(accountName, contactaddress)
	if err := account.Load(); err != nil {
		fmt.Printf("no account found, (error : %s)\n", err)
		fmt.Printf("So Registering new account \n")
		if err := account.Register(context.Background(), ca.acme_client); err != nil {
			fmt.Println(err) //account retrieved by private key if the json gets deleted
			if err := account.GetAccount(context.Background(), ca.acme_client); err != nil {
				fmt.Println(err)
			}
		}
	}
}

func (ca *client) Order4Domain(domainAddress string) {
	order := orders.New(domainAddress)
	order.Create(context.Background(), ca.acme_client)
	order.Finish(ca.acme_client)
}
