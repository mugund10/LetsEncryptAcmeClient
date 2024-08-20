package leacme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

type account struct{}
type csr struct{}

// generates random rsa keys with 2048 bits
func KeyGen() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// saves the rsa keys in pem format
// currently supports rsa, for other type keys specific type assertions need to be implemented
func SaveKey(key any, fname string) error {
	pemKey := &pem.Block{}
	if pkey, ok := key.(*rsa.PrivateKey); ok {
		pemKey = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pkey),
		}
	} else {
		return errors.New("unsupported key type")
	}

	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, pemKey)
}
