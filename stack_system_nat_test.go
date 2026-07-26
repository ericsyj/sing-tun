package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

func TestTCPNatLookupPreservesDestination(t *testing.T) {
	nat := newTCPNatForTest(time.Minute)
	source := netip.MustParseAddrPort("192.0.2.1:10000")
	firstDestination := netip.MustParseAddrPort("198.51.100.1:443")
	secondDestination := netip.MustParseAddrPort("198.51.100.2:443")

	firstPort := nat.Lookup(source, firstDestination, header.TCPFlagSyn)
	secondPort := nat.Lookup(source, secondDestination, header.TCPFlagSyn)
	if firstPort == secondPort {
		t.Fatal("connections to different destinations share a NAT port")
	}
	if currentPort := nat.Lookup(source, firstDestination, header.TCPFlagAck); currentPort != firstPort {
		t.Fatalf("existing mapping changed from %d to %d", firstPort, currentPort)
	}
}

func TestTCPNatLookupReclaimsExpiredAndClosedPorts(t *testing.T) {
	const firstNATPort = 10000
	timeout := time.Minute
	now := time.Now()
	nat := newTCPNatForTest(timeout)
	sourceAddress := netip.MustParseAddr("192.0.2.1")
	destination := netip.MustParseAddrPort("198.51.100.1:443")
	for natPort := firstNATPort; natPort <= 65535; natPort++ {
		source := netip.AddrPortFrom(sourceAddress, uint16(natPort))
		session := &TCPSession{
			Source:      source,
			Destination: destination,
			LastActive:  now,
		}
		nat.addrMap[tcpNatKey{Source: source, Destination: destination}] = uint16(natPort)
		nat.portMap[uint16(natPort)] = session
	}

	newSource := netip.MustParseAddrPort("192.0.2.2:9999")
	newDestination := netip.MustParseAddrPort("203.0.113.1:443")
	if natPort := nat.Lookup(newSource, newDestination, header.TCPFlagSyn); natPort != 0 {
		t.Fatalf("reclaimed non-expired NAT port %d", natPort)
	}

	expiredSession := nat.portMap[firstNATPort]
	expiredKey := tcpNatKey{
		Source:      expiredSession.Source,
		Destination: expiredSession.Destination,
	}
	expiredSession.LastActive = now.Add(-2 * timeout)
	if natPort := nat.Lookup(newSource, newDestination, header.TCPFlagSyn); natPort != firstNATPort {
		t.Fatalf("expected expired NAT port %d, got %d", firstNATPort, natPort)
	}
	if _, loaded := nat.addrMap[expiredKey]; loaded {
		t.Fatal("expired address mapping was not removed")
	}
	if natPort := nat.addrMap[tcpNatKey{Source: newSource, Destination: newDestination}]; natPort != firstNATPort {
		t.Fatalf("new address mapping uses NAT port %d", natPort)
	}

	closedPort := uint16(firstNATPort + 1)
	closedKey := tcpNatKey{
		Source:      nat.portMap[closedPort].Source,
		Destination: nat.portMap[closedPort].Destination,
	}
	anotherSource := netip.MustParseAddrPort("192.0.2.2:9998")
	anotherDestination := netip.MustParseAddrPort("203.0.113.2:443")
	if natPort := nat.Lookup(anotherSource, anotherDestination, header.TCPFlagSyn); natPort != 0 {
		t.Fatalf("reclaimed open NAT port %d", natPort)
	}
	if nat.LookupBack(closedPort, header.TCPFlagRst) == nil {
		t.Fatal("failed to look up NAT session")
	}
	if natPort := nat.Lookup(anotherSource, anotherDestination, header.TCPFlagSyn); natPort != closedPort {
		t.Fatalf("expected closed NAT port %d, got %d", closedPort, natPort)
	}
	if _, loaded := nat.addrMap[closedKey]; loaded {
		t.Fatal("closed address mapping was not removed")
	}
}

func newTCPNatForTest(timeout time.Duration) *TCPNat {
	return &TCPNat{
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[tcpNatKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
}
