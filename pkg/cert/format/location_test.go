package format

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSplitString(t *testing.T) {
	t.Run("given string when longer than size then it is split", func(t *testing.T) {
		someString := "some long string that we want to split multiple times"
		out := SplitString(someString, "  ", 6)
		for _, v := range out {
			// cannot be more than size + prefix
			assert.True(t, len(v) <= 8)
		}
		assert.True(t, len(out) > 2)
	})

	t.Run("given string when shorter than size then it is not split", func(t *testing.T) {
		someString := "some string"
		out := SplitString(someString, "  ", 50)
		require.Equal(t, 1, len(out))
		// prefix was added
		assert.Equal(t, len(someString)+2, len(out[0]))
	})
}
