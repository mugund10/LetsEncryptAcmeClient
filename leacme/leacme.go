package leacme

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/mugund10/LetsEncryptAcmeClient/account"
	"github.com/mugund10/LetsEncryptAcmeClient/orders"
	"golang.org/x/crypto/acme"
)

// defaults
var (
	productionurl string = "https://acme-v02.api.letsencrypt.org/directory"
	stagingurl    string = "https://acme-staging-v02.api.letsencrypt.org/directory"

// filename      string = "orgAccount.json"
)

// default url is staging
var url *string = &stagingurl
// switches the url to production url
func Switchurl() {
	url = &productionurl
}
// resets the url back to staging url
func Reseturl() {
	url = &stagingurl
}
// changes the url to given url
func Newurl(nurl string) {
	url = &nurl
}

type client struct {
	acme_client *acme.Client
}

//creates new client with given private key
//to change the url from production to staging call leacme.Reseturl()
//or staging to production call leacme.Switchurl()
//for custom url call lecame.Newurl()
func NewClient(pkey *rsa.PrivateKey) client {
	var ca client
	client := acme.Client{Key: pkey, DirectoryURL: *url}
	ca.acme_client = &client
	return ca
}

// registers a new account with acme server or
// retrieves old registered account with the given private key
// ( for contactaddress use this "mailto:example@example.com" format )
func (ca *client) RegisterAccount(accountName string, contactaddress string) {

	account := account.New(accountName, contactaddress)
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
	//return account
}

func (ca *client) OrderDomain(domainAddress string){
	order := orders.New(domainAddress)
	order.Make(context.Background(),ca.acme_client)
}



