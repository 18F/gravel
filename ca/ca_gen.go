package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	rand2 "math/rand"
	"time"
)

// A root certificate that can be used for testing purposes.
type GravelCertificateChain struct {
	RootCertificatePublicKey  []byte
	RootCertificatePrivateKey []byte

	ca *x509.Certificate
}

// todo (mxplusb): the certificate extraction logic could be it's own function but is it really necessary?

// Generates an on-demand root certificate.
func GenerateGravelRootCertificateChain() (*GravelCertificateChain, error) {

	gcc := &GravelCertificateChain{}

	gcc.ca = &x509.Certificate{
		SerialNumber: big.NewInt(rand2.Int63()),
		Subject: pkix.Name{
			Organization:       []string{"18F"},
			OrganizationalUnit: []string{"cloud.gov"},
			Country:            []string{"US"},
			Province:           []string{"Colorado"},
			Locality:           []string{"Boulder"},
			StreetAddress:      []string{""},
			PostalCode:         []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	ca_b, err := x509.CreateCertificate(rand.Reader, gcc.ca, gcc.ca, pub, priv)
	if err != nil {
		return &GravelCertificateChain{}, fmt.Errorf("create ca failed: %s", err)
	}

	// Public key
	var publicKeyOutFile bytes.Buffer
	if err := pem.Encode(&publicKeyOutFile, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b}); err != nil {
		return &GravelCertificateChain{}, err
	}
	_, err = publicKeyOutFile.Write(gcc.RootCertificatePrivateKey)
	if err != nil {
		return &GravelCertificateChain{}, err
	}

	// Private key
	var privateKeyOutFile bytes.Buffer
	if err := pem.Encode(&privateKeyOutFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return &GravelCertificateChain{}, err
	}
	_, err = privateKeyOutFile.Write(gcc.RootCertificatePrivateKey)
	if err != nil {
		return &GravelCertificateChain{}, err
	}

	return gcc, nil
}

// Generate a certificate from the root CA. Returns the public key, the private key, and an error.
func (gcc *GravelCertificateChain) GenerateCertificate() ([]byte, []byte, error) {

	var publicKey, privateKey []byte

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// generate our template.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(rand2.Int63()),
		Subject: pkix.Name{
			Organization:       []string{"18F"},
			OrganizationalUnit: []string{"cloud.gov"},
			Country:            []string{"US"},
			Province:           []string{"Colorado"},
			Locality:           []string{"Boulder"},
			StreetAddress:      []string{""},
			PostalCode:         []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	pub := &priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, gcc.ca, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	var publicKeyOutFile bytes.Buffer
	if err := pem.Encode(&publicKeyOutFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return nil, nil, err
	}
	_, err = publicKeyOutFile.Write(publicKey)
	if err != nil {
		return nil, nil, err
	}

	var privateKeyOutFile bytes.Buffer
	if err := pem.Encode(&privateKeyOutFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return nil, nil, err
	}
	_, err = privateKeyOutFile.Write(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}
