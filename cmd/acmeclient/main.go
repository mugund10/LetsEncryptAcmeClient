package main

import (
	"github.com/mugund10/LetsEncryptAcmeClient"
)

func main() {
	key := letsencryptacmeclient.NewKey("account")
	client := letsencryptacmeclient.NewClient(key, true)
	client.RegisterAccount("mugund10", "mailto:example@gmail.com")
	client.GetTLS("homeserver.mugund10.top")

}
