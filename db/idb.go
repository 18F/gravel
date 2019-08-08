package db

import (
	"crypto"
	"math/big"

	"github.com/18f/gravel/acme"
	"github.com/18f/gravel/core"
	"gopkg.in/square/go-jose.v2"
)

// Interface reference for a database.
type GravelStore interface {
	GetAccountByID(id string) *core.Account
	GetAccountByKey(key crypto.PublicKey) (*core.Account, error)

	// Note that this function should *NOT* be used for key changes. It assumes
	// the public key associated to the account does not change. Use ChangeAccountKey
	// to change the account's public key.
	UpdateAccountByID(id string, acct *core.Account) error
	AddAccount(acct *core.Account) (int, error)
	ChangeAccountKey(acct *core.Account, newKey *jose.JSONWebKey) error
	AddOrder(order *core.Order) (int, error)
	GetOrderByID(id string) *core.Order
	AddAuthorization(authz *core.Authorization) (int, error)
	GetAuthorizationByID(id string) *core.Authorization

	// FindValidAuthorization fetches the first, if any, valid and unexpired authorization for the
	// provided identifier, from the ACME account matching accountID.
	FindValidAuthorization(accountID string, identifier acme.Identifier) *core.Authorization
	AddChallenge(chal *core.Challenge) (int, error)
	GetChallengeByID(id string) *core.Challenge
	AddCertificate(cert *core.Certificate) (int, error)
	GetCertificateByID(id string) *core.Certificate
	GetCertificateByDER(der []byte) *core.Certificate
	GetRevokedCertificateByDER(der []byte) *core.RevokedCertificate
	RevokeCertificate(cert *core.RevokedCertificate)
	GetCertificateBySerial(serialNumber *big.Int) *core.Certificate
	GetRevokedCertificateBySerial(serialNumber *big.Int) *core.RevokedCertificate

	// Handles notifications in and out of the database.
	NotificationHandler()
}
