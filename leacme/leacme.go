package LetsEncryptAcmeClient

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/mugund10/LetsEncryptAcmeClient/Account"
	"github.com/mugund10/LetsEncryptAcmeClient/errs"
	"github.com/mugund10/LetsEncryptAcmeClient/keys"
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

// creates new rsa key with the given name or
// if you already have a private key in the pem
// form just use the name of the file
func NewKey(keyName string) *rsa.PrivateKey {
	key := keys.New()
	err := key.RsaGen(keyName)
	errs.CheckError(err)
	reads := key.LoadPem()
	if reads != nil {
		fmt.Println("key not found locally, so saving newly generated key")
		saves := key.SaveAsPem()
		errs.CheckError(saves)
	}
	return key.Private
}

// creates new client with given private key
// for stagingUrl ("https://acme-staging-v02.api.letsencrypt.org/directory") value must be true
// if its false productionUrl will be used  productionurl string "https://acme-v02.api.letsencrypt.org/directory"
// for "pkey" use leacme.NewKey()
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

//gets tls certificates from Certificate Authority(letsEncrypt.org)
func (ca *client) GetTLS(domainAddress string) {
	order := orders.New(domainAddress)
	order.Create(context.Background(), ca.acme_client)
	order.Finish(ca.acme_client)
}
