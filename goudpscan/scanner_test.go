package goudpscan_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KernelPryanic/goudpscan/goudpscan"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOptions(t *testing.T) {
	options := goudpscan.NewOptions(true, uint(10), uint8(3), 2)

	assert.NotNil(t, options, "NewOptions should not return nil")
}

func TestNewScanner(t *testing.T) {
	scanner := goudpscan.New(
		[]string{"127.0.0.1"},
		[]string{"80"},
		map[uint16][]string{},
		goudpscan.NewOptions(true, uint(10), uint8(3), 2),
	)

	assert.NotNil(t, scanner, "New should not return nil")
}

func TestSegmentation(t *testing.T) {
	tests := []struct {
		subnet   string
		expected []string
	}{
		{"192.168.0.1", []string{"192", "168", "0", "1"}},
		{"10.0.0.0/24", []string{"10", "0", "0", "0", "24"}},
		{"10.0.0.1-10", []string{"10", "0", "0", "1-10"}},
		{"10.0.0.1-10/24", []string{"10", "0", "0", "1-10", "24"}},
	}

	for _, test := range tests {
		segments := goudpscan.Segmentation(test.subnet)
		require.Equal(t, test.expected, segments)
	}
}

func TestBreakUpIP(t *testing.T) {
	tests := []struct {
		segments    []string
		expected    []string
		expectedErr bool
	}{
		{segments: []string{"192", "168", "0", "1"}, expected: []string{"192.168.0.1"}},
		{segments: []string{"10", "0", "0", "1-3"}, expected: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{
			segments: []string{"10", "0-1", "0", "1-3"},
			expected: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.1.0.1", "10.1.0.2", "10.1.0.3"},
		},
		{
			segments:    []string{"10", "0,1-2", "0", "24"},
			expectedErr: true,
		},
		{
			segments:    []string{"10", "0-1,1", "0", "24"},
			expectedErr: true,
		},
		{
			segments:    []string{"10", "0-1", "0,1-1", "24"},
			expectedErr: true,
		},
	}

	for _, test := range tests {
		ips, err := goudpscan.BreakUpIP(test.segments)
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
		expected    []string
		expectedErr bool
	}{
		{subnet: "192.168.0.1", expected: []string{"192.168.0.1"}},
		{subnet: "10.0.0.0/24", expected: []string{"10.0.0.0/24"}},
		{subnet: "10.0.0.1-4", expected: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}},
		{subnet: "10.0.0.1-2/24", expected: []string{"10.0.0.1/24", "10.0.0.2/24"}},
		{subnet: "10.0,1-2.1-2/24", expectedErr: true},
		{subnet: "10.0,1-2.1-2", expectedErr: true},
	}

	for _, test := range tests {
		subnets, err := goudpscan.ParseSubnet(test.subnet)
		if test.expectedErr {
			require.Error(t, err)
		} else {
			require.Equal(t, test.expected, subnets)
		}
	}
}

func TestBreakUPPort(t *testing.T) {
	tests := []struct {
		portRange   string
		expected    []uint16
		expectedErr bool
	}{
		{portRange: "80", expected: []uint16{80}},
		{portRange: "22-25", expected: []uint16{22, 23, 24, 25}},
		{portRange: "22-25,80", expected: []uint16{22, 23, 24, 25, 80}},
		{portRange: "80.0", expectedErr: true},
		{portRange: "22.2-25", expectedErr: true},
		{portRange: "22-25.5", expectedErr: true},
	}

	for _, test := range tests {
		ports, err := goudpscan.BreakUPPort(test.portRange)
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
		cidr        string
		expected    []string
		expectedErr bool
	}{
		{
			name:     "Single IP",
			cidr:     "192.168.1.1",
			expected: []string{"192.168.1.1"},
		},
		{
			name:     "CIDR /30",
			cidr:     "192.168.1.0/30",
			expected: []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name:        "Invalid CIDR",
			cidr:        "192.168.1.256/24",
			expectedErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := goudpscan.Hosts(test.cidr)
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
	opts := goudpscan.NewOptions(true, 1, 0, 1)

	sc := goudpscan.New(hosts, ports, payloads, opts)

	// Create a context to stop the SniffICMP function
	ctx, cancel := context.WithCancel(context.Background())

	// Run the SniffICMP function in a separate goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := sc.SniffICMP(ctx, &wg); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("SniffICMP failed: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	// Run the Scan function
	scanResult, err := sc.Scan(&log.Logger)
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}

	// Check the result of the scan
	expectedKey := "127.0.0.1:80"
	if _, ok := scanResult[expectedKey]; !ok {
		t.Errorf("Scan result does not contain the expected key: %s", expectedKey)
	}
	require.Len(t, scanResult, 1)

	// Stop the SniffICMP function
	cancel()
	wg.Wait()
}
