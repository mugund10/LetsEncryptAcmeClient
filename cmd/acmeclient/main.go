package main

import (
	"log"

	"github.com/mugund10/LetsEncryptAcmeClient"
)

func main() {
	keys , err := leacme.KeyGen()
	chechError(err)	
	saves := leacme.SaveKey(keys,"test.pem")
	chechError(saves)
}

func chechError(err error){
	if err != nil {
		log.Println(err)
	}
}