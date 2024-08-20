package main

import (
	"fmt"
	"log"

	"github.com/mugund10/LetsEncryptAcmeClient"
)

func main() {
	keys , err := leacme.KeyGen()
	chechError(err)	
	saves := leacme.SaveKey(keys,"test.pem")
	chechError(saves)

	Pkey , err := leacme.ReadKey("test.pem")
	chechError(err)
	fmt.Println(Pkey)
}

func chechError(err error){
	if err != nil {
		log.Println(err)
	}
}