package dns

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewDefaultIntegrationServerOpts(t *testing.T) {

	// we just assign a logger to ensure the values are the same.

	at := assert.New(t)

	trh := make(chan DnsMessage, 10)

	expected := &IntegrationServerOpts{
		AutoUpdateAuthZRecords: true,
		BaseDomain:             "service",
		DnsPort:                5454,
		Logger:                 logrus.New(),
		Provider:               NewDnsProvider(trh),
		AlreadyHashed:          false,
	}

	actual := NewDefaultIntegrationServerOpts()

	// test not nil since the memory addresses are always going to be different
	at.NotNil(actual.Logger, "the logger should not be nil")
	at.NotNil(actual.Provider, "the provider should not be nil")

	at.EqualValues(expected.AutoUpdateAuthZRecords, actual.AutoUpdateAuthZRecords, "auto updating dns records should be enabled")
	at.EqualValues(expected.BaseDomain, actual.BaseDomain, "default base domain should be `service`")
	at.EqualValues(expected.DnsPort, actual.DnsPort, "default dns port should be 5454")

}

func TestNewDefaultIntegrationServer(t *testing.T) {
	at := assert.New(t)

	opts := NewDefaultIntegrationServerOpts()
	d := NewIntegrationServer(opts)

	at.NotNil(d, "integration server must not be nil")
	at.NotNil(d.Opts, "Opts must not be nil for configuration")
	at.NotNil(d.Stopper, "stopper channel must not be nil")
	at.Nil(d.Server, "DNS server must be nil until it is started")
}

func TestIntegrationServerStart(t *testing.T) {
	at := assert.New(t)

	opts := NewDefaultIntegrationServerOpts()
	d := NewIntegrationServer(opts)

	go d.Start()

	_, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", opts.DnsPort))
	at.Nil(err, "there should be not connection errors because the server is started")

	d.Stopper <- struct{}{}
	time.Sleep(3 * time.Second)
}
