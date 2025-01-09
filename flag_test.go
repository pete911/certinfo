package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlags(t *testing.T) {

	t.Run("given empty args and env vars then flags are set to default values", func(t *testing.T) {

		setInput(t, nil, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.False(t, flags.Expiry)
		assert.False(t, flags.Insecure)
		assert.False(t, flags.Chains)
		assert.False(t, flags.Pem)
		assert.False(t, flags.PemOnly)
		assert.False(t, flags.Version)
		assert.Empty(t, flags.Args)
	})

	t.Run("given args are set and env vars empty then flags are set to provided args", func(t *testing.T) {

		setInput(t, []string{"flag",
			"-expiry=true",
			"-insecure=true",
			"-chains=true",
			"-chains=true",
			"-pem=true",
			"-pem-only=true",
			"-version=true",
		}, nil)

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.True(t, flags.Expiry)
		assert.True(t, flags.Insecure)
		assert.True(t, flags.Chains)
		assert.True(t, flags.Pem)
		assert.True(t, flags.PemOnly)
		assert.True(t, flags.Version)
		assert.Empty(t, flags.Args)
	})

	t.Run("given args are not set and env vars are set then flags are set to provided env vars", func(t *testing.T) {

		setInput(t, []string{"flag"}, map[string]string{
			"CERTINFO_EXPIRY":   "true",
			"CERTINFO_INSECURE": "true",
			"CERTINFO_CHAINS":   "true",
			"CERTINFO_PEM":      "true",
			"CERTINFO_PEM_ONLY": "true",
			"CERTINFO_VERSION":  "true",
		})

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.True(t, flags.Expiry)
		assert.True(t, flags.Insecure)
		assert.True(t, flags.Chains)
		assert.True(t, flags.Pem)
		assert.True(t, flags.PemOnly)
		assert.True(t, flags.Version)
		assert.Empty(t, flags.Args)
	})

	t.Run("given args are set and env vars are set then flags are set to provided args", func(t *testing.T) {

		setInput(t, []string{"flag",
			"-insecure=true",
			"-chains=true",
			"-pem=false",
			"-version=false",
		}, map[string]string{
			"CERTINFO_EXPIRY":   "true",
			"CERTINFO_CHAINS":   "true",
			"CERTINFO_PEM":      "true",
			"CERTINFO_PEM_ONLY": "true",
			"CERTINFO_VERSION":  "true",
		})

		flags, err := ParseFlags()
		require.NoError(t, err)

		assert.True(t, flags.Expiry)
		assert.True(t, flags.Insecure)
		assert.True(t, flags.Chains)
		assert.False(t, flags.Pem)
		assert.True(t, flags.PemOnly)
		assert.False(t, flags.Version)
		assert.Empty(t, flags.Args)
	})
}

// --- helper functions ---

func setInput(t *testing.T, args []string, env map[string]string) {

	osArgs := os.Args
	if args == nil {
		args = []string{"test"}
	}

	os.Args = args
	for k, v := range env {
		os.Setenv(k, v)
	}

	t.Cleanup(func() {
		os.Args = osArgs
		for k := range env {
			os.Unsetenv(k)
		}
	})
}
