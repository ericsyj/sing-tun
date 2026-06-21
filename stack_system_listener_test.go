package tun

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemAcceptLoopSourceAddresses(t *testing.T) {
	system := System{
		inet4NextAddress: netip.MustParseAddr("172.18.0.2"),
		inet6NextAddress: netip.MustParseAddr("fdfe:dcba:9876::2"),
	}

	testCases := []struct {
		name   string
		remote netip.Addr
		valid  bool
	}{
		{
			name:   "IPv4 TUN peer",
			remote: netip.MustParseAddr("172.18.0.2"),
			valid:  true,
		},
		{
			name:   "IPv4-mapped TUN peer",
			remote: netip.MustParseAddr("::ffff:172.18.0.2"),
			valid:  true,
		},
		{
			name:   "IPv6 TUN peer",
			remote: netip.MustParseAddr("fdfe:dcba:9876::2"),
			valid:  true,
		},
		{
			name:   "TUN interface address",
			remote: netip.MustParseAddr("172.18.0.1"),
			valid:  false,
		},
		{
			name:   "external address",
			remote: netip.MustParseAddr("2001:db8::1"),
			valid:  false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.valid, system.isTCPSourceAddress(testCase.remote))
		})
	}
}
