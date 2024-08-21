package main

import (
	"fmt"
	"log"

	"github.com/mugund10/LetsEncryptAcmeClient/keys"
	"github.com/mugund10/LetsEncryptAcmeClient/leacme"
)

func main() {
	// ctx := context.Background()
	//ra := keys.GetMain()
	key := keys.New()
	// key1 := keys.New()
	err := key.KeyGen("account")
	chechError(err)
	// err = key1.KeyGen("account1")
	// chechError(err)
	// fmt.Println(key.Private)

	reads := key.LoadKey() 
	if reads != nil {
		fmt.Println("key not found locally, so saving newly generated key")
		saves := key.SaveKey()
		chechError(saves)
	}

	client := leacme.NewClient(key.Private)
	client.RegisterAccount("mugund10","mailto:example@gmail.com" )

	// saves = key1.SaveKey()
	// chechError(saves)

	
	
	// fmt.Println(key.Private)
	// // _ = Pkey
	// cl := leacme.NewClient(Pkey)
	// // na := leacme.NewAccount("mailto:bjmugundhan2000@gmail.com")
	// // ra = leacme.AccountRegister(ctx, cl, na)
	// // leacme.SaveAccount("ra.json")
	// leacme.LoadAccount("ra.json")
	// ra := leacme.GetMain()
	// fmt.Println(ra)

	// domain := leacme.AddDomain("homeserver.mugund10.top")
	// leacme.MakeOrder(ctx, cl, *domain)

}

func chechError(err error) {
	if err != nil {
		log.Println(err)
	}
}
