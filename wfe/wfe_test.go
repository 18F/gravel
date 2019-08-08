package wfe

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultWebFrontEndOpts(t *testing.T) {
	expected := &WebFrontEndOpts{
		DirectoryPath:                "/dir",
		NoncePath:                    "/nonce-plz",
		NewAccountPath:               "/sign-me-up",
		AcctPath:                     "/my-account/",
		NewOrderPath:                 "/order-plz",
		OrderPath:                    "/my-order/",
		OrderFinalizePath:            "/finalize-order/",
		AuthzPath:                    "/authZ/",
		ChallengePath:                "/chalZ/",
		CertPath:                     "/certZ/",
		RevokeCertPath:               "/revoke-cert",
		KeyRolloverPath:              "/rollover-account-key",
		RootCertPath:                 "/roots/",
		RootKeyPath:                  "/root-keys/",
		IntermediateCertPath:         "/intermediates/",
		IntermediateKeyPath:          "/intermediate-keys/",
		CertStatusBySerial:           "/cert-status-by-serial/",
		PendingAuthzExpire:           time.Hour,
		MaxContactsPerAcct:           2,
		BadNoncePercentage:           0,
		DefaultNonceReject:           5,
		UnusedRevocationReason:       7,
		AACompromiseRevocationReason: 10,
		AuthzReusePercentage:         0,
		DefaultAuthzReuse:            50,
	}

	actual := NewDefaultWebFrontEndOpts()

	assert.ObjectsAreEqual(expected, actual)
}
