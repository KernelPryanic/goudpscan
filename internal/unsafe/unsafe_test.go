package unsafe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestB2S(t *testing.T) {
	for _, s := range []string{
		"", "abc", "abc defg", "ёшф qxl щж1234¯˙¬£",
	} {
		t.Run("", func(t *testing.T) {
			b := []byte(s)
			u := B2S(b)
			require.Equal(t, s, u)
		})
	}
}

func TestB2SNil(t *testing.T) {
	b := []byte(nil)
	u := B2S(b)
	require.Zero(t, u)
}

func TestS2B(t *testing.T) {
	for _, s := range []string{
		"abc", "abc defg", "ёшф qxl щж1234¯˙¬£",
	} {
		t.Run("", func(t *testing.T) {
			expect := make([]byte, len(s))
			copy(expect, s)
			b := S2B(s)
			require.Equal(t, expect, b)
		})
	}
}

func TestS2BEmpty(t *testing.T) {
	b := S2B("")
	require.Nil(t, b)
}
