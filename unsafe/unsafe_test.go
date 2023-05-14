package unsafe_test

import (
	"testing"

	"github.com/KernelPryanic/goudpscan/unsafe"
	"github.com/stretchr/testify/require"
)

func TestB2S(t *testing.T) {
	for _, s := range []string{
		"", "abc", "abc defg", "ёшф qxl щж1234¯˙¬£",
	} {
		t.Run("", func(t *testing.T) {
			b := []byte(s)
			u := unsafe.B2S(b)
			require.Equal(t, s, u)
		})
	}
}
