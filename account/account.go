package account

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/acme"
)

type accountMan struct {
	accountHolder *acme.Account
	fname         string
}

// creates new account for your certificates
// the contact should be like mailto:abc.gmail.com
func New(accountName string, contact string) accountMan {
	var am accountMan
	acme_account := acme.Account{Contact: []string{contact}}
	am.accountHolder = &acme_account
	am.fname = accountName
	return am
}

// Registers your account with lets Encrypt
func (am *accountMan) Register(ctx context.Context, client *acme.Client) error {
	mainAccount, err := client.Register(ctx, am.accountHolder, acme.AcceptTOS) // terms of service function not yet implemented
	if err != nil {
		return err
	}
	am.accountHolder = mainAccount
	am.saveAccount()
	return nil
}

// saves the mainAccount data into json
func (am *accountMan) saveAccount() error {
	fname := fmt.Sprintf("%s.json", am.fname)
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	newEncoder := json.NewEncoder(file)
	return newEncoder.Encode(&am.accountHolder)
}

// loads the json file data into mainAccount
func (am *accountMan) Load() error {
	fname := fmt.Sprintf("%s.json", am.fname)
	file, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer file.Close()
	newDecoder := json.NewDecoder(file)
	return newDecoder.Decode(&am.accountHolder)

}

// retrieves account using private key
func (am *accountMan) GetAccount(ctx context.Context, client *acme.Client) error {
	mainAccount, err := client.GetReg(ctx, am.accountHolder.URI)
	if err != nil {
		fmt.Println("not matched so updating")
		return err
	}
	am.accountHolder = mainAccount
	am.saveAccount()
	return nil
}
