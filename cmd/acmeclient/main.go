package main

import (
	"fmt"

	"github.com/mugund10/LetsEncryptAcmeClient/errs"
	"github.com/mugund10/LetsEncryptAcmeClient/keys"
	"github.com/mugund10/LetsEncryptAcmeClient/leacme"
)

func main() {
	key := keys.New()
	err := key.RsaGen("account")
	errs.CheckError(err)
	reads := key.LoadPem()
	if reads != nil {
		fmt.Println("key not found locally, so saving newly generated key")
		saves := key.SaveAsPem()
		errs.CheckError(saves)
	}
	client := leacme.NewClient(key.Private,true)
	client.RegisterAccount("mugund10", "mailto:example@gmail.com")
	client.Order4Domain("homeserver.mugund10.top")

}
