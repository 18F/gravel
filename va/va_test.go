package va

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultVerificationAuthorityOpts(t *testing.T) {

	expected := &VerificationAuthorityOpts{
		WhitespaceCutset:                  "\n\r\t",
		UserAgentBase:                     "18f-Gravel-VA",
		ValidAuthzExpire:                  time.Hour,
		TaskQueueSize:                     6,
		ConcurrentValidations:             3,
		NoSleep:                           true,
		VerificationSleepDuration:         0 * time.Second,
		DefaultValidationAttemptSleepTime: 5 * time.Second,
		ValidationTimeout:                 15 * time.Second,
		NoValidate:                        false,
		HttpPort:                          5001,
		TlsPort:                           5002,
		CustomResolverAddress:             "",
	}

	actual := NewDefaultVerificationAuthorityOpts()

	assert.ObjectsAreEqualValues(expected, actual)
}
