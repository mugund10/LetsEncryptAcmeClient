package leacme

import (
	"crypto/rsa"

	"golang.org/x/crypto/acme"
)

// type account struct{}
// type csr struct{}
var (
	productionurl string = "https://acme-v02.api.letsencrypt.org/directory"
	stagingurl    string = "https://acme-staging-v02.api.letsencrypt.org/directory"
	filename      string = "orgAccount.json"
)
var err error


var url *string = &stagingurl //default url is staging

func Switchurl() {
	url = &productionurl
}
func Reseturl() {
	url = &stagingurl
}
func Newurl(nurl string) {
	url = &nurl
}

func NewClient(pkey *rsa.PrivateKey) *acme.Client {
	client := acme.Client{Key: pkey, DirectoryURL: *url}
	return &client
}
