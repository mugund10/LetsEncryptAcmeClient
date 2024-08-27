package main

import (
	"github.com/mugund10/LetsEncryptAcmeClient/leacme"
)

func main() {
	key := LetsEncryptAcmeClient.NewKey("account")
	client := LetsEncryptAcmeClient.NewClient(key, true)
	client.RegisterAccount("mugund10", "mailto:example@gmail.com")
	client.GetTLS("homeserver.mugund10.top")

}
