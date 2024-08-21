package leacme

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/mugund10/LetsEncryptAcmeClient/account"
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

type Client struct {
	acme *acme.Client
}

//creates new client with given private key
//to change the url from production to staging call leacme.Reseturl()
//or staging to production call leacme.Switchurl()
//for custom url call lecame.Newurl()

func NewClient(pkey *rsa.PrivateKey) Client {
	var ca Client
	client := acme.Client{Key: pkey, DirectoryURL: *url}
	ca.acme = &client
	return ca
}

//register a new account with acme server or
//loads the old Registered account with same account name or
//even changes the privkey of the account if its not same.
//( for contactaddress use "mailto:example@example.com" )
func(ca Client) RegisterAccount(accountName string, contactaddress string){


	account := account.NewAccount(accountName,contactaddress)
	if err := account.Load(); err != nil {
		fmt.Printf("no account found, (error : %s)\n",err)
		fmt.Printf("So Registering new account \n")
		if err := account.Register(context.Background(),ca.acme); err != nil{
			fmt.Println(err)
		 }
		 fmt.Println("from Register",account)
	}else{

		fmt.Println("from load",account)
	} 

}



// adds the domain or subdomain for your order
func AddDomain(addr string) *[]acme.AuthzID {
	domain := []acme.AuthzID{{Type: "dns", Value: addr}}
	return &domain
}
