package leacme

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"golang.org/x/crypto/acme"
)

var mainAccount *acme.Account

func GetMain() *acme.Account {
	return mainAccount
}

// the contact should be like mailto:abc.gmail.com
func NewAccount(contact string) *acme.Account {
	acc := acme.Account{Contact: []string{contact}}
	return &acc
}

func AccountRegister(ctx context.Context, client *acme.Client, Acc *acme.Account) *acme.Account {
	mainAccount, err = client.Register(ctx, Acc, acme.AcceptTOS)
	if err != nil {
		log.Fatal("error registering account : ", err)
	}
	return mainAccount
}

// saves the mainAccount data into json
func SaveAccount(fname string) error {
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	newEncoder := json.NewEncoder(file)
	return newEncoder.Encode(&mainAccount)
}

// loads the json file data into mainAccount
func LoadAccount(fname string) error {
	file, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	newDecoder := json.NewDecoder(file)
	return newDecoder.Decode(&mainAccount)

}
