[![Documentation](https://godoc.org/github.com/18f/gravel?status.svg)](http://godoc.org/github.com/18f/gravel)

# Gravel

Gravel is an integration environment for Let's Encrypt.

If you're wondering why it's called _Gravel_, the reference ACME server is called [Boulder](https://github.com/letsencrypt/boulder), and it has a development server for infrastructure testing called [Pebble](https://github.com/letsencrypt/pebble), since it's smaller than Boulder. Well, Gravel is smaller than a Pebble.

The project came from [Pebble#241](https://github.com/letsencrypt/pebble/pull/241) as both a tool and thought experiment on what an integration environment for Let's Encrypt would look like.

As part of that, the core of this project is a hard fork from Pebble at [7228963](https://github.com/letsencrypt/pebble/commit/7228963479dd2bce0c040049b18e67393155bc6a), so it's license is MPL-2.0. While this is a work of employees of the United States Government and our specific contributions are public domain, MPL-2.0's requirements require us to keep it licensed as MPL-2.0. For more information on this policy, see [this document](https://github.com/18F/open-source-policy/blob/master/policy.md#open-source-licenses).

## Consuming It

For the most part, consuming the integration environment is pretty straightforward.

```go
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/18f/gravel"
	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {

	opts := gravel.NewDefaultGravelOpts()
	opts.VAOpts.CustomResolverAddress = fmt.Sprintf("localhost:%d", opts.DnsOpts.DnsPort)
	g, _ := gravel.New(opts)

	// start the servers.
	go g.StartDnsServer()
	go g.StartWebServer()
	time.Sleep(3 * time.Second)

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	myuser := MyUser{
		Email: "test@test.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&myuser)
	config.HTTPClient = g.Client
	config.Certificate.KeyType = certcrypto.RSA2048
	config.CADirURL = fmt.Sprintf("https://%s%s", g.Opts.ListenAddress, g.Opts.WfeOpts.DirectoryPath)

	client, _ := lego.NewClient(config)

	_ = client.Challenge.SetDNS01Provider(
		g.Opts.DnsOpts.Provider,
		dns01.AddRecursiveNameservers([]string{
			fmt.Sprintf("127.0.0.1:%d", g.Opts.DnsOpts.DnsPort),
		}),
		dns01.WrapPreCheck(g.DnsServer.PreCheck))

	reg, _ := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})

	myuser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{"test.service"},
		Bundle:  true,
	}

	certificates, _ := client.Certificate.Obtain(request)

	// do something with your valid certificate pair.
}
```

See the documentation on all the hooks and features available.

## Developing

For the most part, it's pretty straightfoward, you can run tests with `go test -v ./...`.
