package main

import (
	leacme "github.com/mugund10/LetsEncryptAcmeClient/leacme"
)

func main() {
	key := leacme.NewKey("account")
	
	client := leacme.NewClient(key, true)
	client.RegisterAccount("mugund10", "mailto:example@gmail.com")
	client.GetTLS("homeserver.mugund10.top")

}
