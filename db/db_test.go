package db

import (
	"testing"

	"github.com/18f/gravel/core"
	"github.com/stretchr/testify/assert"
)

func TestNewDefaultDatabaseOpts(t *testing.T) {
	expected := &DatabaseOpts{
		AccountNotifier:       make(chan *core.Account, 10),
		AuthorizationNotifier: make(chan *core.Authorization, 10),
		ChallengeNotifier:     make(chan *core.Challenge, 10),
		CertificateNotifier:   make(chan *core.Certificate, 10),
		OrderNotifier:         make(chan *core.Order, 10),
		RevocationNotifier:    make(chan *core.RevokedCertificate, 10),
		NotifyOnUpdate:        false,
		Receiver:              make(chan interface{}),
	}

	actual := NewDefaultDatabaseOpts()

	assert.ObjectsAreEqualValues(expected, actual)
}
