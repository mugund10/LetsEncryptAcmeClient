package main

import (
	"fmt"
	"log"

	"github.com/mugund10/LetsEncryptAcmeClient/keys"
	"github.com/mugund10/LetsEncryptAcmeClient/leacme"
)

func main() {
	key := keys.New()
	err := key.KeyGen("account")
	chechError(err)
	reads := key.LoadKey()
	if reads != nil {
		fmt.Println("key not found locally, so saving newly generated key")
		saves := key.SaveKey()
		chechError(saves)
	}
	client := leacme.NewClient(key.Private)
	client.RegisterAccount("mugund10", "mailto:example@gmail.com")
	client.OrderDomain("homeserver.mugund10.top")

}

func chechError(err error) {
	if err != nil {
		log.Println(err)
	}
}
