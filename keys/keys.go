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
//type for keymanagement
type keyMan struct {
	Private *rsa.PrivateKey
	name    string
}
//type for csrmanagement
type csrMan struct {
	Bytes []byte
	name  string
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
	PemBlock := &pem.Block{
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
	return pem.Encode(file, PemBlock)
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

// default implementation of csr
// due to lack of study
func (km *keyMan) CsrGen(domains []string) (csrMan, error) {
	var cm csrMan
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
		return cm, err
	}
	cm.Bytes = csrBytes
	cm.name = km.name
	return cm, nil
}

func (cm *csrMan) SaveAsPem() error {
	fname := fmt.Sprintf("csr(%s).pem", cm.name)
	Pemblock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: cm.Bytes,
	})
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the PEM-encoded CSR to the file
	_, err = file.Write(Pemblock)
	if err != nil {
		return err
	}

	return nil
}

func (cm *csrMan) LoadPem() error {
	fname := fmt.Sprintf("csr(%s).pem", cm.name)
	// Reads the PEM file into a byte slice
	pemData, err := os.ReadFile(fname)
	if err != nil {
		return err
	}
	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return errors.New("failed to decode PEM block containing the CSR")
	}
	// Parse the CSR from the PEM block
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	// Verify the CSR
	if err := csr.CheckSignature(); err != nil {
		return err
	}
	cm.Bytes = block.Bytes
	return nil
}

