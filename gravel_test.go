package gravel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/stretchr/testify/assert"
)

func TestNewDefaultGravelOpts(t *testing.T) {
	at := assert.New(t)

	gopts := NewDefaultGravelOpts()

	at.NotEmpty(gopts, "Core defaults should not be empty")
	at.NotEmpty(gopts.Logger, "Logger should be instantiated for downstream consumption")
	at.NotEmpty(gopts.DnsOpts, "DnsOpts are needed to build the integration DNS server")
	at.NotEmpty(gopts.WfeOpts, "WfeOpts are needed to ensure the WFE starts properly")
	at.NotEmpty(gopts.DatabaseOpts, "DatabaseOpts are needed to configure the memory store")
	at.NotEmpty(gopts.CAOpts, "CAOpts are needed to configure the core CA")
	at.NotEmpty(gopts.VAOpts, "VAOpts are needed to ensure the VA starts properly")
	at.Empty(gopts.EnableTestIntegration, "EnableTestIntegration should be false in default opts.")
	at.NotEmpty(gopts.ListenAddress, "ListenAddress cannot be nil as it's needed to start the Let's Encrypt server.")
}

func TestNewWithDefaults(t *testing.T) {
	at := assert.New(t)

	g, err := New(NewDefaultGravelOpts())
	at.Nil(err, "there should not be an error on instantiation")

	at.NotEmpty(g, "Gravel should not be nil")
	at.NotEmpty(g.Client, "Gravel HTTP client should not be nil")
	at.NotEmpty(g.Logger, "Gravel logger should not be nil")
	at.NotEmpty(g.CertificateAuthority, "Gravel Certificate Authority should not be nil")
	at.NotEmpty(g.WebFrontEnd, "Gravel WFE should not be nil")
	at.NotEmpty(g.VerificationAuthority, "Gravel VA should not be nil")
	at.NotEmpty(g.Database, "Gravel memory store should not be nil")
	at.NotEmpty(g.DnsServer, "Gravel DNS server should not be nil")

	at.Empty(g.CertificateServer, "Gravel Certificate Server should be nil as it's not started yet")

	l, err := net.Dial("tcp", fmt.Sprintf(":%d", g.Opts.DnsOpts.DnsPort))
	at.Error(err, "TCP connection to the DNS server should error because it's not started yet")
	at.Nil(l, "connection interface should be empty")
}

func TestGravelStartDnsServer(t *testing.T) {
	at := assert.New(t)

	opts := NewDefaultGravelOpts()
	g, err := New(opts)
	at.Nil(err, "there should not be an error on instantiation")

	go g.StartDnsServer()

	_, err = net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", opts.DnsOpts.DnsPort))
	at.Nil(err, "there should be not connection errors because the server is started")

	g.DnsServer.Stopper <- struct{}{}
	time.Sleep(3 * time.Second)
}

func TestGravelStartWebServer(t *testing.T) {
	at := assert.New(t)

	opts := NewDefaultGravelOpts()
	g, err := New(opts)
	at.Nil(err, "there should not be an error on instantiation")

	go g.StartWebServer()
	time.Sleep(3 * time.Second)

	_, err = net.Dial("tcp", opts.ListenAddress)
	at.Nil(err, "there should not be an error when dialing the web server")

	err = g.CertificateServer.Shutdown(context.Background())
	at.Nil(err, "there should not be an error when stopping the server")
}

type TestUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *TestUser) GetEmail() string {
	return u.Email
}
func (u TestUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *TestUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func TestGravelWithDNSCertificate(t *testing.T) {
	at := assert.New(t)

	opts := NewDefaultGravelOpts()
	opts.VAOpts.CustomResolverAddress = fmt.Sprintf("localhost:%d", opts.DnsOpts.DnsPort)
	g, err := New(opts)
	at.Nil(err, "there should not be an error on instantiation")

	// start the servers.
	go g.StartDnsServer()
	go g.StartWebServer()
	time.Sleep(3 * time.Second)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	at.Nil(err, "there should be no error when generating a certificate")

	tu := TestUser{
		Email: "test@test.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&tu)
	config.HTTPClient = g.Client
	config.Certificate.KeyType = certcrypto.RSA2048
	config.CADirURL = fmt.Sprintf("https://%s%s", g.Opts.ListenAddress, g.Opts.WfeOpts.DirectoryPath)

	client, err := lego.NewClient(config)
	at.Nil(err, "there should not be an error when instantiating a new let's encrypt client")

	err = client.Challenge.SetDNS01Provider(
		g.Opts.DnsOpts.Provider,
		dns01.AddRecursiveNameservers([]string{
			fmt.Sprintf("127.0.0.1:%d", g.Opts.DnsOpts.DnsPort),
		}),
		dns01.WrapPreCheck(g.DnsServer.PreCheck))
	at.Nil(err, "client dns challenge configuration should be nil")

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	at.Nil(err, "there should be no registration errors")

	tu.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{"test.service"},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	at.Nil(err, "there should be no error obtaining a certificate")

	at.NotEmpty(certificates, "certificates should not be empty")

	at.EqualValues("test.service", certificates.Domain, "certificate domain should match")
}
