package tun

import (
	"net"
	"net/netip"
	"testing"
)

func TestIsDirectRedirectConnection(t *testing.T) {
	localAddr := &net.TCPAddr{
		IP:   net.ParseIP("192.168.16.2"),
		Port: 20179,
	}

	testCases := []struct {
		name                string
		originalDestination netip.AddrPort
		expected            bool
	}{
		{
			name:                "same IPv4 address and port",
			originalDestination: netip.MustParseAddrPort("192.168.16.2:20179"),
			expected:            true,
		},
		{
			name:                "same IPv4 mapped IPv6 address and port",
			originalDestination: netip.MustParseAddrPort("[::ffff:192.168.16.2]:20179"),
			expected:            true,
		},
		{
			name:                "different port",
			originalDestination: netip.MustParseAddrPort("192.168.16.2:20180"),
			expected:            false,
		},
		{
			name:                "different address",
			originalDestination: netip.MustParseAddrPort("192.168.16.3:20179"),
			expected:            false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if actual := isDirectRedirectConnection(localAddr, testCase.originalDestination); actual != testCase.expected {
				t.Errorf("isDirectRedirectConnection() = %v, want %v", actual, testCase.expected)
			}
		})
	}
}
