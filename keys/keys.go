// rsa key type only implemented
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type keyMan struct {
	Private *rsa.PrivateKey
	name    string
}

// creates a new instance
func New() keyMan {
	var km keyMan
	return km
}

// generates random rsa keys with 2048 bits
func (km *keyMan) RsaGen(keyname string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	km.Private = key
	km.name = keyname
	return nil
}

// use keys.LoadKey() first to ensure there is no key present locally in the same name
// otherwise it will overwrite the old key with same name
// saves the RSA PrivateKey into pem format,
func (km *keyMan) SaveAsPem() error {
	keyname := fmt.Sprintf("%s.pem", km.name)
	pemKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(km.Private),
	}
	// open a new file
	file, err := os.Create(keyname)
	if err != nil {
		return err
	}
	defer file.Close()
	// write the encoded data to the file
	return pem.Encode(file, pemKey)
}

// loads the pemfile into RSA PrivateKey format
func (km *keyMan) LoadPem() error {
	keyname := fmt.Sprintf("%s.pem", km.name)
	//open the pemfile
	file, err := os.Open(keyname)
	if err != nil {
		return err
	}
	defer file.Close()
	//read the entire content into slice of bytes
	bytesInFile := make([]byte, 2048)
	nos, err := file.Read(bytesInFile)
	if err != nil {
		return err
	}
	//decode the pem blocks from byte slices
	Pemblock, _ := pem.Decode(bytesInFile[:nos])
	if Pemblock == nil || Pemblock.Type != "RSA PRIVATE KEY" {
		return errors.New("failed to decode pem")
	}
	//Parse the RSA private key from the decoded bytes
	pkey, err := x509.ParsePKCS1PrivateKey(Pemblock.Bytes)
	if err != nil {
		return err
	}
	km.Private = pkey
	return nil
}

//default implementation of csr 
//due to lack of study
func (km *keyMan) CsrGen(domains []string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domains[0],
			Country:    []string{"IN"},
		},
		DNSNames:           domains,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	// Generate the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, req, km.Private)
	if err != nil {
		return nil, err
	}
	return csrBytes , nil
}
