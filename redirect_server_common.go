package tun

import (
	"net"
	"net/netip"

	M "github.com/sagernet/sing/common/metadata"
)

// isDirectRedirectConnection reports whether a connection was made directly
// to the redirect listener instead of being redirected there. In that case,
// SO_ORIGINAL_DST is the listener address itself. Routing it as a transparent
// connection would dial the listener recursively.
func isDirectRedirectConnection(localAddr net.Addr, originalDestination netip.AddrPort) bool {
	return M.SocksaddrFromNet(localAddr).Unwrap() == M.SocksaddrFromNetIP(originalDestination).Unwrap()
}
