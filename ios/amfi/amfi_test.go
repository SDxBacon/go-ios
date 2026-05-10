package amfi

import (
	"errors"
	"testing"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/stretchr/testify/assert"
)

func TestNewRejectsRsdDevice(t *testing.T) {
	device := ios.DeviceEntry{
		Rsd: ios.RsdHandshakeResponse{
			Services: map[string]ios.RsdServiceEntry{},
		},
	}

	_, err := New(device)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAMFIRequiresUSB))
}
