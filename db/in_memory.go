package db

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/18f/gravel/acme"
	"github.com/18f/gravel/core"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
)

// ExistingAccountError is an error type indicating when an operation fails
// because the MatchingAccount has a key conflict.
type ExistingAccountError struct {
	MatchingAccount *core.Account
}

func (e ExistingAccountError) Error() string {
	return fmt.Sprintf("New public key is already in use by account %s", e.MatchingAccount.ID)
}

// Gravel's internal database for handling records. Information here is designed to be exported through notifiers, as
// seen in DatabaseOpts.
type InMemoryStore struct {
	mu sync.RWMutex

	accountIDCounter int

	accountsByID map[string]*core.Account

	// Each Accounts's key ID is the hex encoding of a SHA256 sum over its public
	// key bytes.
	accountsByKeyID map[string]*core.Account

	ordersByID map[string]*core.Order

	authorizationsByID map[string]*core.Authorization

	challengesByID map[string]*core.Challenge

	certificatesByID        map[string]*core.Certificate
	revokedCertificatesByID map[string]*core.RevokedCertificate

	// internal references to the notifiers.
	opts *DatabaseOpts
}

// Options for implementing notifiers. If fields are nil, messages are dropped. Notification channels are designed for
// live updates from the database for closer testing, if needed.
type DatabaseOpts struct {
	AccountNotifier       chan *core.Account
	AuthorizationNotifier chan *core.Authorization
	ChallengeNotifier     chan *core.Challenge
	CertificateNotifier   chan *core.Certificate
	OrderNotifier         chan *core.Order
	RevocationNotifier    chan *core.RevokedCertificate

	// Send notifications on updates. If set to true, updated records will be sent to the notification channels along
	// with new records.
	NotifyOnUpdate bool

	// Message router.
	Receiver chan interface{}

	// Logger
	Logger *logrus.Logger
}

// Generate some default configurations for the database. All channels are set to a length of 10, NotifyOnUpdate is set
// to false.
func NewDefaultDatabaseOpts() *DatabaseOpts {
	return &DatabaseOpts{
		AccountNotifier:       make(chan *core.Account, 10),
		AuthorizationNotifier: make(chan *core.Authorization, 10),
		ChallengeNotifier:     make(chan *core.Challenge, 10),
		CertificateNotifier:   make(chan *core.Certificate, 10),
		OrderNotifier:         make(chan *core.Order, 10),
		RevocationNotifier:    make(chan *core.RevokedCertificate, 10),
		Receiver:              make(chan interface{}),
		Logger:                logrus.New(),
	}
}

func NewMemoryStore(opts *DatabaseOpts) GravelStore {

	ref := opts
	ref.Receiver = make(chan interface{}, 1)

	ims := &InMemoryStore{
		accountIDCounter:        0,
		accountsByID:            make(map[string]*core.Account),
		accountsByKeyID:         make(map[string]*core.Account),
		ordersByID:              make(map[string]*core.Order),
		authorizationsByID:      make(map[string]*core.Authorization),
		challengesByID:          make(map[string]*core.Challenge),
		certificatesByID:        make(map[string]*core.Certificate),
		revokedCertificatesByID: make(map[string]*core.RevokedCertificate),
		opts:                    ref,
	}

	go ims.NotificationHandler()
	return ims
}

// Handle the internal message routing.
func (m *InMemoryStore) NotificationHandler() {
	for {
		select {
		case payload := <-m.opts.Receiver:
			switch payload.(type) {
			case *core.Account:
				if m.opts.AccountNotifier != nil {
					m.opts.AccountNotifier <- payload.(*core.Account)
				}
			case *core.Authorization:
				if m.opts.AuthorizationNotifier != nil {
					m.opts.AuthorizationNotifier <- payload.(*core.Authorization)
				}
			case *core.Challenge:
				if m.opts.ChallengeNotifier != nil {
					m.opts.ChallengeNotifier <- payload.(*core.Challenge)
				}
			case *core.Certificate:
				if m.opts.CertificateNotifier != nil {
					m.opts.CertificateNotifier <- payload.(*core.Certificate)
				}
			case *core.Order:
				if m.opts.OrderNotifier != nil {
					m.opts.OrderNotifier <- payload.(*core.Order)
				}
			case *core.RevokedCertificate:
				if m.opts.RevocationNotifier != nil {
					m.opts.RevocationNotifier <- payload.(*core.RevokedCertificate)
				}
			default: // drop otherwise.
				_ = payload
			}
		}
	}
}

func (m *InMemoryStore) GetAccountByID(id string) *core.Account {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.accountsByID[id]
}

func (m *InMemoryStore) GetAccountByKey(key crypto.PublicKey) (*core.Account, error) {
	keyID, err := keyToID(key)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.accountsByKeyID[keyID], nil
}

func (m *InMemoryStore) UpdateAccountByID(id string, acct *core.Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accountsByID[id] == nil {
		return fmt.Errorf("account with ID %q does not exist", id)
	}
	keyID, err := keyToID(acct.Key)
	if err != nil {
		return err
	}
	m.accountsByID[id] = acct
	m.accountsByKeyID[keyID] = acct

	// send the updated account to the handler for upstream consumption.
	if m.opts.NotifyOnUpdate {
		m.opts.Receiver <- acct
	}

	return nil
}

func (m *InMemoryStore) AddAccount(acct *core.Account) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	acctID := strconv.Itoa(m.accountIDCounter)
	m.accountIDCounter++

	if acct.Key == nil {
		return 0, fmt.Errorf("account must not have a nil Key")
	}

	keyID, err := keyToID(acct.Key)
	if err != nil {
		return 0, err
	}

	if _, present := m.accountsByID[acctID]; present {
		return 0, fmt.Errorf("account %q already exists", acctID)
	}

	if _, present := m.accountsByKeyID[keyID]; present {
		return 0, fmt.Errorf("account with key already exists")
	}

	acct.ID = acctID
	m.accountsByID[acctID] = acct
	m.accountsByKeyID[keyID] = acct

	// send the account to the handler for upstream consumption.
	m.opts.Receiver <- acct

	return len(m.accountsByID), nil
}

func (m *InMemoryStore) ChangeAccountKey(acct *core.Account, newKey *jose.JSONWebKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldKeyID, err := keyToID(acct.Key)
	if err != nil {
		return err
	}

	newKeyID, err := keyToID(newKey)
	if err != nil {
		return err
	}

	if otherAccount, present := m.accountsByKeyID[newKeyID]; present {
		return ExistingAccountError{otherAccount}
	}

	delete(m.accountsByKeyID, oldKeyID)
	acct.Key = newKey
	m.accountsByKeyID[newKeyID] = acct
	m.accountsByID[acct.ID] = acct

	// send the updated account to the handler for upstream consumption.
	if m.opts.NotifyOnUpdate {
		m.opts.Receiver <- acct
	}

	return nil
}

func (m *InMemoryStore) AddOrder(order *core.Order) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	order.RLock()
	orderID := order.ID
	if len(orderID) == 0 {
		return 0, fmt.Errorf("order must have a non-empty ID to add to InMemoryStore")
	}
	order.RUnlock()

	if _, present := m.ordersByID[orderID]; present {
		return 0, fmt.Errorf("order %q already exists", orderID)
	}

	m.ordersByID[orderID] = order

	m.opts.Receiver <- order

	return len(m.ordersByID), nil
}

func (m *InMemoryStore) GetOrderByID(id string) *core.Order {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if order, ok := m.ordersByID[id]; ok {
		orderStatus, err := order.GetStatus()
		if err != nil {
			panic(err)
		}
		order.Lock()
		defer order.Unlock()
		order.Status = orderStatus
		return order
	}
	return nil
}

func (m *InMemoryStore) AddAuthorization(authz *core.Authorization) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	authz.RLock()
	authzID := authz.ID
	if len(authzID) == 0 {
		return 0, fmt.Errorf("authz must have a non-empty ID to add to InMemoryStore")
	}
	authz.RUnlock()

	if _, present := m.authorizationsByID[authzID]; present {
		return 0, fmt.Errorf("authz %q already exists", authzID)
	}

	m.authorizationsByID[authzID] = authz

	m.opts.Receiver <- authz

	return len(m.authorizationsByID), nil
}

func (m *InMemoryStore) GetAuthorizationByID(id string) *core.Authorization {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.authorizationsByID[id]
}

func (m *InMemoryStore) FindValidAuthorization(accountID string, identifier acme.Identifier) *core.Authorization {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, authz := range m.authorizationsByID {
		if authz.Status == acme.StatusValid && identifier.Equals(authz.Identifier) &&
			authz.Order != nil && authz.Order.AccountID == accountID &&
			authz.ExpiresDate.After(time.Now()) {
			return authz
		}
	}
	return nil
}

func (m *InMemoryStore) AddChallenge(chal *core.Challenge) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	chal.RLock()
	chalID := chal.ID
	chal.RUnlock()
	if len(chalID) == 0 {
		return 0, fmt.Errorf("challenge must have a non-empty ID to add to InMemoryStore")
	}

	if _, present := m.challengesByID[chalID]; present {
		return 0, fmt.Errorf("challenge %q already exists", chalID)
	}

	m.challengesByID[chalID] = chal

	m.opts.Receiver <- chal

	return len(m.challengesByID), nil
}

func (m *InMemoryStore) GetChallengeByID(id string) *core.Challenge {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.challengesByID[id]
}

func (m *InMemoryStore) AddCertificate(cert *core.Certificate) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	certID := cert.ID
	if len(certID) == 0 {
		return 0, fmt.Errorf("cert must have a non-empty ID to add to InMemoryStore")
	}

	if _, present := m.certificatesByID[certID]; present {
		return 0, fmt.Errorf("cert %q already exists", certID)
	}
	if _, present := m.revokedCertificatesByID[certID]; present {
		return 0, fmt.Errorf("cert %q already exists (and is revoked)", certID)
	}

	m.certificatesByID[certID] = cert

	m.opts.Receiver <- cert

	return len(m.certificatesByID), nil
}

func (m *InMemoryStore) GetCertificateByID(id string) *core.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.certificatesByID[id]
}

// GetCertificateByDER loops over all certificates to find the one that matches the provided DER bytes.
// This method is linear and it's not optimized to give you a quick response.
func (m *InMemoryStore) GetCertificateByDER(der []byte) *core.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.certificatesByID {
		if reflect.DeepEqual(c.DER, der) {
			return c
		}
	}

	return nil
}

// GetCertificateByDER loops over all revoked certificates to find the one that matches the provided
// DER bytes. This method is linear and it's not optimized to give you a quick response.
func (m *InMemoryStore) GetRevokedCertificateByDER(der []byte) *core.RevokedCertificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.revokedCertificatesByID {
		if reflect.DeepEqual(c.Certificate.DER, der) {
			return c
		}
	}

	return nil
}

func (m *InMemoryStore) RevokeCertificate(cert *core.RevokedCertificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedCertificatesByID[cert.Certificate.ID] = cert
	delete(m.certificatesByID, cert.Certificate.ID)

	m.opts.Receiver <- cert
}

/*
 * keyToID produces a string with the hex representation of the SHA256 digest
 * over a provided public key. We use this to associate public keys to
 * acme.Account objects, and to ensure every account has a unique public key.
 */
func keyToID(key crypto.PublicKey) (string, error) {
	switch t := key.(type) {
	case *jose.JSONWebKey:
		if t == nil {
			return "", fmt.Errorf("cannot compute ID of nil key")
		}
		return keyToID(t.Key)
	case jose.JSONWebKey:
		return keyToID(t.Key)
	default:
		keyDER, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		spkiDigest := sha256.Sum256(keyDER)
		return hex.EncodeToString(spkiDigest[:]), nil
	}
}

// GetCertificateBySerial loops over all certificates to find the one that matches the provided
// serial number. This method is linear and it's not optimized to give you a quick response.
func (m *InMemoryStore) GetCertificateBySerial(serialNumber *big.Int) *core.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.certificatesByID {
		if serialNumber.Cmp(c.Cert.SerialNumber) == 0 {
			return c
		}
	}

	return nil
}

// GetRevokedCertificateBySerial loops over all revoked certificates to find the one that matches the
// provided serial number. This method is linear and it's not optimized to give you a quick
// response.
func (m *InMemoryStore) GetRevokedCertificateBySerial(serialNumber *big.Int) *core.RevokedCertificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.revokedCertificatesByID {
		if serialNumber.Cmp(c.Certificate.Cert.SerialNumber) == 0 {
			return c
		}
	}

	return nil
}
