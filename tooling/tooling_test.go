package tooling

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestFormPayload(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: nil}).Level(zerolog.DebugLevel)
	testCases := []struct {
		payloadMap map[string][]string
		expected   map[uint16][]string
	}{
		{
			payloadMap: map[string][]string{
				"80": {`\r12345678Q999\x00`},
				"623": {
					`\x06\x00\xff\x06
					\x00\x00\x11\xbe
					\x80\x00\x00\x00`,
					`\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18
					\xc8\x81\x00\x38\x8e\x04\xb5`,
				},
			},
			expected: map[uint16][]string{
				80: {`\r12345678Q999\x00`},
				623: {
					`\x06\x00\xff\x06
					\x00\x00\x11\xbe
					\x80\x00\x00\x00`,
					`\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18
					\xc8\x81\x00\x38\x8e\x04\xb5`,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			actual, err := FormPayload(&logger, tc.payloadMap)
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestMergeSortAsync(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "versions",
			input:    []string{"2.0.0", "1.0.0", "3.1.0", "3.0.1"},
			expected: []string{"1.0.0", "2.0.0", "3.0.1", "3.1.0"},
		},
		{
			name:     "IPs",
			input:    []string{"192.168.1.2", "192.168.0.1", "192.168.1.1"},
			expected: []string{"192.168.0.1", "192.168.1.1", "192.168.1.2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resultChan := make(chan []string, 1)
			MergeSortAsync(tc.input, resultChan)
			actual := <-resultChan
			require.Equal(t, tc.expected, actual)
		})
	}
}
