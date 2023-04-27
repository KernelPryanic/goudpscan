package goudpscan_test

import (
	"reflect"
	"testing"

	"github.com/KernelPryanic/goudpscan/goudpscan"
)

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
		if !equal(segments, test.expected) {
			t.Errorf("Segmentation(%q) = %v; expected %v", test.subnet, segments, test.expected)
		}
	}
}

func TestBreakUpIP(t *testing.T) {
	tests := []struct {
		segments []string
		expected []string
	}{
		{[]string{"192", "168", "0", "1"}, []string{"192.168.0.1"}},
		{[]string{"10", "0", "0", "1-3"}, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{[]string{"10", "0-1", "0", "1-3"}, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.1.0.1", "10.1.0.2", "10.1.0.3"}},
	}

	for _, test := range tests {
		ips, err := goudpscan.BreakUpIP(test.segments)
		if err != nil {
			t.Errorf("BreakUpIP(%v) returned an error: %v", test.segments, err)
			continue
		}
		if !equal(ips, test.expected) {
			t.Errorf("BreakUpIP(%v) = %v; expected %v", test.segments, ips, test.expected)
		}
	}
}

func TestParseSubnet(t *testing.T) {
	tests := []struct {
		subnet   string
		expected []string
	}{
		{"192.168.0.1", []string{"192.168.0.1"}},
		{"10.0.0.0/24", []string{"10.0.0.0/24"}},
		{"10.0.0.1-4", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}},
		{"10.0.0.1-2/24", []string{"10.0.0.1/24", "10.0.0.2/24"}},
	}

	for _, test := range tests {
		subnets, err := goudpscan.ParseSubnet(test.subnet)
		if err != nil {
			t.Errorf("ParseSubnet(%q) returned an error: %v", test.subnet, err)
			continue
		}
		if !equal(subnets, test.expected) {
			t.Errorf("ParseSubnet(%q) = %v; expected %v", test.subnet, subnets, test.expected)
		}
	}
}

func TestBreakUPPort(t *testing.T) {
	tests := []struct {
		portRange string
		expected  []uint16
	}{
		{"80", []uint16{80}},
		{"22-25", []uint16{22, 23, 24, 25}},
	}

	for _, test := range tests {
		ports, err := goudpscan.BreakUPPort(test.portRange)
		if err != nil {
			t.Errorf("BreakUPPort(%q) returned an error: %v", test.portRange, err)
			continue
		}
		if !equalInt(ports, test.expected) {
			t.Errorf("BreakUPPort(%q) = %v; expected %v", test.portRange, ports, test.expected)
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
			name:        "Single IP",
			cidr:        "192.168.1.1",
			expected:    []string{"192.168.1.1"},
			expectedErr: false,
		},
		{
			name:        "CIDR /30",
			cidr:        "192.168.1.0/30",
			expected:    []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
			expectedErr: false,
		},
		{
			name:        "Invalid CIDR",
			cidr:        "192.168.1.256/24",
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := goudpscan.Hosts(tt.cidr)
			if (err != nil) != tt.expectedErr {
				t.Errorf("Hosts() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("Hosts() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// Helper function to compare two string slices
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Helper function to compare two int slices
func equalInt(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
