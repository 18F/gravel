package ca

import (
	"crypto/rsa"

	"github.com/18f/gravel/core"
)

type ICertificateAuthority interface {
	CompleteOrder(order *core.Order)
	GetNumberOfRootCerts() int
	GetRootCert(no int) *core.Certificate
	GetRootKey(no int) *rsa.PrivateKey
	GetIntermediateCert(no int) *core.Certificate
	GetIntermediateKey(no int) *rsa.PrivateKey
}
