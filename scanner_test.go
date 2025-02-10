package goudpscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KernelPryanic/goudpscan/internal/unsafe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOptions(t *testing.T) {
	options := NewOptions(true, uint(10), uint8(3), 2)

	assert.NotNil(t, options)
}

func TestNewScanner(t *testing.T) {
	scanner := New(
		NewOptions(true, uint(10), uint8(3), 2),
		[]string{"127.0.0.1"},
		[]string{"80"},
		map[uint16][]string{},
	)

	assert.NotNil(t, scanner)
}

func TestSegmentation(t *testing.T) {
	tests := []struct {
		subnet   []byte
		expected [][]byte
	}{
		{[]byte("192.168.0.1"), [][]byte{[]byte("192"), []byte("168"), []byte("0"), []byte("1")}},
		{[]byte("10.0.0.0/24"), [][]byte{[]byte("10"), []byte("0"), []byte("0"), []byte("0"), []byte("24")}},
		{[]byte("10.0.0.1-10"), [][]byte{[]byte("10"), []byte("0"), []byte("0"), []byte("1-10")}},
		{[]byte("10.0.0.1-10/24"), [][]byte{[]byte("10"), []byte("0"), []byte("0"), []byte("1-10"), []byte("24")}},
	}

	for _, test := range tests {
		segments := Segmentation(test.subnet)
		require.Equal(t, test.expected, segments)
	}
}

func TestBreakUpIP(t *testing.T) {
	tests := []struct {
		segments    [][]byte
		expected    [][]byte
		expectedErr bool
	}{
		{
			segments: [][]byte{[]byte("192"), []byte("168"), []byte("0"), []byte("1")},
			expected: [][]byte{[]byte("192.168.0.1")},
		},
		{
			segments: [][]byte{[]byte("10"), []byte("0"), []byte("0"), []byte("1-3")},
			expected: [][]byte{[]byte("10.0.0.1"), []byte("10.0.0.2"), []byte("10.0.0.3")},
		},
		{
			segments: [][]byte{[]byte("10"), []byte("0-1"), []byte("0"), []byte("1-3")},
			expected: [][]byte{[]byte("10.0.0.1"), []byte("10.0.0.2"), []byte("10.0.0.3"), []byte("10.1.0.1"), []byte("10.1.0.2"), []byte("10.1.0.3")},
		},
		{
			segments:    [][]byte{[]byte("10"), []byte("0,1-2"), []byte("0"), []byte("24")},
			expectedErr: true,
		},
		{
			segments:    [][]byte{[]byte("10"), []byte("0-1,1"), []byte("0"), []byte("24")},
			expectedErr: true,
		},
		{
			segments:    [][]byte{[]byte("10"), []byte("0-1"), []byte("0,1-1"), []byte("24")},
			expectedErr: true,
		},
	}

	for _, test := range tests {
		ips, err := BreakUpIP(test.segments)
		if test.expectedErr {
			require.Error(t, err)
		} else {
			require.Equal(t, test.expected, ips)
		}
	}
}

func TestParseSubnet(t *testing.T) {
	tests := []struct {
		subnet      string
		expected    [][]byte
		expectedErr bool
	}{
		{subnet: "192.168.0.1", expected: [][]byte{[]byte("192.168.0.1")}},
		{subnet: "10.0.0.0/24", expected: [][]byte{[]byte("10.0.0.0/24")}},
		{subnet: "10.0.0.1-4", expected: [][]byte{[]byte("10.0.0.1"), []byte("10.0.0.2"), []byte("10.0.0.3"), []byte("10.0.0.4")}},
		{subnet: "10.0.0.1-2/24", expected: [][]byte{[]byte("10.0.0.1/24"), []byte("10.0.0.2/24")}},
		{subnet: "10.0,1-2.1-2/24", expectedErr: true},
		{subnet: "10.0,1-2.1-2", expectedErr: true},
	}

	for _, test := range tests {
		subnets, err := ParseSubnet(unsafe.S2B(test.subnet))
		if test.expectedErr {
			require.Error(t, err)
		} else {
			require.Equal(t, test.expected, subnets)
		}
	}
}

func TestBreakUPPort(t *testing.T) {
	tests := []struct {
		portRange   []byte
		expected    []uint16
		expectedErr bool
	}{
		{portRange: []byte("80"), expected: []uint16{80}},
		{portRange: []byte("22-25"), expected: []uint16{22, 23, 24, 25}},
		{portRange: []byte("22-25,80"), expected: []uint16{22, 23, 24, 25, 80}},
		{portRange: []byte("80.0"), expectedErr: true},
		{portRange: []byte("22.2-25"), expectedErr: true},
		{portRange: []byte("22-25.5"), expectedErr: true},
	}

	for _, test := range tests {
		ports, err := BreakUPPort(test.portRange)
		if test.expectedErr {
			require.Error(t, err)
		} else {
			require.Equal(t, test.expected, ports)
		}
	}
}

func TestHosts(t *testing.T) {
	tests := []struct {
		name        string
		cidr        []byte
		expected    [][]byte
		expectedErr bool
	}{
		{
			name:     "Single IP",
			cidr:     []byte("192.168.1.1"),
			expected: [][]byte{[]byte("192.168.1.1")},
		},
		{
			name:     "CIDR /30",
			cidr:     []byte("192.168.1.0/30"),
			expected: [][]byte{[]byte("192.168.1.0"), []byte("192.168.1.1"), []byte("192.168.1.2"), []byte("192.168.1.3")},
		},
		{
			name:        "Invalid CIDR",
			cidr:        []byte("192.168.1.256/24"),
			expectedErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Hosts(test.cidr)
			if test.expectedErr {
				require.Error(t, err)
			} else {
				require.Equal(t, test.expected, got)
			}
		})
	}
}

func TestScan(t *testing.T) {
	hosts := []string{"127.0.0.1"}
	ports := []string{"80"}
	payloads := make(map[uint16][]string)
	opts := NewOptions(true, 1, 0, 1)

	sc := New(opts, hosts, ports, payloads)

	// Create a context to stop the SniffICMP function
	ctx, cancel := context.WithCancel(context.Background())

	// Run the SniffICMP function in a separate goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := sc.SniffICMP(ctx, &wg); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("ICMP sniffing failed: %v", err)
		}
	}()

	time.Sleep(250 * time.Millisecond)

	errorsCh := make(chan error, 8)
	ctx, cancelErrHandler := context.WithCancel(context.Background())
	go HelperErrorHandler(t, ctx, errorsCh)
	// Run the Scan function
	scanResult := sc.Scan(errorsCh, time.Now().UnixNano())

	// Check the result of the scan
	expectedKey := "127.0.0.1:80"
	if _, ok := scanResult[expectedKey]; !ok {
		t.Errorf("scan result does not contain the expected key: %s", expectedKey)
	}
	require.Len(t, scanResult, 1)

	// Stop the SniffICMP function
	cancel()
	cancelErrHandler()
	wg.Wait()
}

func HelperErrorHandler(t *testing.T, ctx context.Context, errorsCh <-chan error) {
	for {
		select {
		case err := <-errorsCh:
			t.Errorf("scan failed: %v", err)
		case <-ctx.Done():
			return
		}
	}
}
