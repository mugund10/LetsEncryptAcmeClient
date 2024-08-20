package leacme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// generates random rsa keys with 2048 bits
func KeyGen() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// saves the RSA PrivateKey into pem format,
// currently supports rsa, for other type keys 
//specific type assertions need to be implemented
func SaveKey(key any, fname string) error {
	var pemKey *pem.Block

	// check if the key of the type of RSA PrivateKey
	if pkey, ok := key.(*rsa.PrivateKey); ok {
		pemKey = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(pkey),
		}
	} else {
		return errors.New("unsupported key type")
	}

	// open a new file
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	// write the encoded data to the file
	return pem.Encode(file, pemKey)
}

//reads the pemfile then decodes it and returns the RSA PrivateKey
func ReadKey(fname string) (*rsa.PrivateKey, error) {

	//open the pemfile
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	//read the entire content into slice of bytes
	bytesInFile := make([]byte, 2048)
	nos, err := file.Read(bytesInFile)
	if err != nil {
		return nil, err
	}

	//decode the pem blocks from byte slices
	Pemblock, _ := pem.Decode(bytesInFile[:nos])
	if Pemblock == nil || Pemblock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode pem")
	}

	//Parse the RSA private key from the decoded bytes
	pkey, err := x509.ParsePKCS1PrivateKey(Pemblock.Bytes)
	if err != nil {
		return nil, err
	}

	return pkey, nil
}
