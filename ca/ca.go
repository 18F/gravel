package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/18f/gravel/acme"
	"github.com/18f/gravel/core"
	"github.com/18f/gravel/db"
	"github.com/sirupsen/logrus"
)

const (
	rootCAPrefix         = "Gravel Root CA "
	intermediateCAPrefix = "Gravel Intermediate CA "
)

// A Gravel certificate authority.
type CertificateAuthority struct {
	// The internal certificate chains used in this CA, mostly used for client-side verification.
	Chains []*Chain

	log              *logrus.Logger
	db               db.GravelStore
	ocspResponderURL string
}

// Options used to configure the certificate authority.
type CertificateAuthorityOpts struct {
	OcspResponderUrl string
	AlternateRoots   int

	// Logger
	Logger *logrus.Logger
}

type Chain struct {
	Root         *Issuer
	Intermediate *Issuer
}

type Issuer struct {
	Key  crypto.Signer
	Cert *core.Certificate
}

func NewDefaultCertificateAuthorityOpts() *CertificateAuthorityOpts {
	return &CertificateAuthorityOpts{
		OcspResponderUrl: "",
		AlternateRoots:   0,
		Logger:           logrus.New(),
	}
}

func New(db db.GravelStore, opts *CertificateAuthorityOpts) *CertificateAuthority {
	ca := &CertificateAuthority{
		log: opts.Logger,
		db:  db,
	}

	if opts.OcspResponderUrl != "" {
		ca.ocspResponderURL = opts.OcspResponderUrl
		ca.log.Printf("setting OCSP responder URL for issued certificates to %q", ca.ocspResponderURL)
	}

	ik, err := makeKey()
	if err != nil {
		// todo (mxplusb): make this not panic; i.e. it should log.
		panic(fmt.Sprintf("error creating new intermediate private key: %s", err.Error()))
	}
	ca.Chains = make([]*Chain, 1+opts.AlternateRoots)
	for i := 0; i < len(ca.Chains); i++ {
		ca.Chains[i] = ca.newChain(ik)
	}
	return ca
}

func makeSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(fmt.Sprintf("unable to create random serial number: %s", err.Error()))
	}
	return serial
}

// makeKey and makeRootCert are adapted from MiniCA:
// https://github.com/jsha/minica/blob/3a621c05b61fa1c24bcb42fbde4b261db504a74f/main.go

// makeKey creates a new 2048 bit RSA private key
func makeKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (ca *CertificateAuthority) makeRootCert(
	subjectKey crypto.Signer,
	subjCNPrefix string,
	signer *Issuer) (*core.Certificate, error) {

	serial := makeSerial()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         subjCNPrefix + hex.EncodeToString(serial.Bytes()[:3]),
			Organization:       []string{"18F"},
			OrganizationalUnit: []string{"cloud.gov"},
			Country:            []string{"US"},
			Province:           []string{"Colorado"},
			Locality:           []string{"Boulder"},
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(30, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames: []string{"localhost"},
	}

	var signerKey crypto.Signer
	var parent *x509.Certificate
	if signer != nil && signer.Key != nil && signer.Cert != nil && signer.Cert.Cert != nil {
		signerKey = signer.Key
		parent = signer.Cert.Cert
	} else {
		signerKey = subjectKey
		parent = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, subjectKey.Public(), signerKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:   hexSerial,
		Cert: cert,
		DER:  der,
	}
	if signer != nil && signer.Cert != nil {
		newCert.Issuers = make([]*core.Certificate, 1)
		newCert.Issuers[0] = signer.Cert
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func (ca *CertificateAuthority) newRootIssuer() (*Issuer, error) {
	// Make a root private key
	rk, err := makeKey()
	if err != nil {
		return nil, err
	}
	// Make a self-signed root certificate
	rc, err := ca.makeRootCert(rk, rootCAPrefix, nil)
	if err != nil {
		return nil, err
	}

	ca.log.Printf("generated new root issuer with serial %s\n", rc.ID)
	return &Issuer{
		Key:  rk,
		Cert: rc,
	}, nil
}

func (ca *CertificateAuthority) newIntermediateIssuer(root *Issuer, ik crypto.Signer) (*Issuer, error) {
	if root == nil {
		return nil, fmt.Errorf("internal error: root must not be nil")
	}

	// Make an intermediate certificate with the root issuer
	ic, err := ca.makeRootCert(ik, intermediateCAPrefix, root)
	if err != nil {
		return nil, err
	}
	ca.log.Printf("generated new intermediate issuer with serial %s", ic.ID)
	return &Issuer{
		Key:  ik,
		Cert: ic,
	}, nil
}

func (ca *CertificateAuthority) newChain(ik crypto.Signer) *Chain {
	root, err := ca.newRootIssuer()
	if err != nil {
		panic(fmt.Sprintf("error creating new root issuer: %s", err.Error()))
	}
	intermediate, err := ca.newIntermediateIssuer(root, ik)
	if err != nil {
		panic(fmt.Sprintf("error creating new intermediate issuer: %s", err.Error()))
	}
	return &Chain{
		Root:         root,
		Intermediate: intermediate,
	}
}

func (ca *CertificateAuthority) newCertificate(domains []string, ips []net.IP, key crypto.PublicKey, accountID string) (*core.Certificate, error) {
	var cn string
	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ips) > 0 {
		cn = ips[0].String()
	} else {
		return nil, fmt.Errorf("must specify at least one domain name or IP address")
	}

	issuer := ca.Chains[0].Intermediate
	if issuer == nil || issuer.Cert == nil {
		return nil, fmt.Errorf("cannot sign certificate - nil issuer")
	}

	serial := makeSerial()
	template := &x509.Certificate{
		DNSNames:    domains,
		IPAddresses: ips,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ca.ocspResponderURL != "" {
		template.OCSPServer = []string{ca.ocspResponderURL}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer.Cert.Cert, key, issuer.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	issuers := make([]*core.Certificate, len(ca.Chains))
	for i := 0; i < len(ca.Chains); i++ {
		issuers[i] = ca.Chains[i].Intermediate.Cert
	}

	hexSerial := hex.EncodeToString(cert.SerialNumber.Bytes())
	newCert := &core.Certificate{
		ID:        hexSerial,
		AccountID: accountID,
		Cert:      cert,
		DER:       der,
		Issuers:   issuers,
	}
	_, err = ca.db.AddCertificate(newCert)
	if err != nil {
		return nil, err
	}
	return newCert, nil
}

func (ca *CertificateAuthority) CompleteOrder(order *core.Order) {
	// Lock the order for reading
	order.RLock()
	// If the order isn't set as beganProcessing produce an error and immediately unlock
	if !order.BeganProcessing {
		ca.log.Printf("error: asked to complete order %s which had false beganProcessing.",
			order.ID)
		order.RUnlock()
		return
	}
	// Unlock the order again
	order.RUnlock()

	// Check the authorizations - this is done by the VA before calling
	// CompleteOrder but we do it again for robustness sake.
	for _, authz := range order.AuthorizationObjects {
		// Lock the authorization for reading
		authz.RLock()
		if authz.Status != acme.StatusValid {
			return
		}
		authz.RUnlock()
	}

	// issue a certificate for the csr
	csr := order.ParsedCSR
	cert, err := ca.newCertificate(csr.DNSNames, csr.IPAddresses, csr.PublicKey, order.AccountID)
	if err != nil {
		ca.log.Printf("error: unable to issue order: %s", err.Error())
		return
	}
	ca.log.Printf("issued certificate serial %s for order %s", cert.ID, order.ID)

	// Lock and update the order to store the issued certificate
	order.Lock()
	order.CertificateObject = cert
	order.Unlock()
}

func (ca *CertificateAuthority) GetNumberOfRootCerts() int {
	return len(ca.Chains)
}

func (ca *CertificateAuthority) getChain(no int) *Chain {
	if 0 <= no && no < len(ca.Chains) {
		return ca.Chains[no]
	}
	return nil
}

func (ca *CertificateAuthority) GetRootCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.Root.Cert
}

func (ca *CertificateAuthority) GetRootKey(no int) *rsa.PrivateKey {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.Root.Key.(type) {
	case *rsa.PrivateKey:
		return key
	}
	return nil
}

func (ca *CertificateAuthority) GetIntermediateCert(no int) *core.Certificate {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}
	return chain.Intermediate.Cert
}

func (ca *CertificateAuthority) GetIntermediateKey(no int) *rsa.PrivateKey {
	chain := ca.getChain(no)
	if chain == nil {
		return nil
	}

	switch key := chain.Intermediate.Key.(type) {
	case *rsa.PrivateKey:
		return key
	}
	return nil
}
