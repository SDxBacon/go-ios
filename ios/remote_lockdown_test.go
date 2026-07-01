package ios

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRemoteDeveloperModeStatus(t *testing.T) {
	enabled, err := parseRemoteDeveloperModeStatus(true)
	assert.NoError(t, err)
	assert.True(t, enabled)

	enabled, err = parseRemoteDeveloperModeStatus(false)
	assert.NoError(t, err)
	assert.False(t, enabled)
}

func TestParseRemoteDeveloperModeStatusRejectsNonBool(t *testing.T) {
	_, err := parseRemoteDeveloperModeStatus("true")
	assert.Error(t, err)
}
