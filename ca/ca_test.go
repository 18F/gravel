package ca

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultCertificateAuthorityOpts(t *testing.T) {
	expected := &CertificateAuthorityOpts{
		OcspResponderUrl: "",
		AlternateRoots:   0,
	}

	actual := NewDefaultCertificateAuthorityOpts()

	assert.ObjectsAreEqualValues(expected, actual)
}
