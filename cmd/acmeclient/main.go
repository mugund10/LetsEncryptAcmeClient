package main

import (
	"fmt"
	"log"

	leacme "github.com/mugund10/LetsEncryptAcmeClient"
)

func main() {
	//ctx := context.Background()
	// ra := leacme.GetMain()
	// keys, err := leacme.KeyGen()
	// chechError(err)
	// saves := leacme.SaveKey(keys, "test.pem")
	// chechError(saves)

	// Pkey, err := leacme.ReadKey("test.pem")
	// chechError(err)
	// //fmt.Println(Pkey)
	// _ = Pkey
	// cl := leacme.NewClient(Pkey)
	// na := leacme.NewAccount("mailto:bjmugundhan2000@gmail.com")
	// ra = leacme.AccountRegister(ctx, cl, na)
	// leacme.SaveAccount("ra.json")
	leacme.LoadAccount("ra.json")
	ra := leacme.GetMain()
	fmt.Println(ra)
}

func chechError(err error) {
	if err != nil {
		log.Println(err)
	}
}
