package tun

import (
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

type localICMPTestHandler struct {
	Handler
	judged atomic.Int32
}

func (h *localICMPTestHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	h.judged.Add(1)
	return FlowVerdict{Action: ActionDrop}
}

// Flow judgment runs asynchronously, so wait for the pending verdict.
func requireLocalICMPJudged(t *testing.T, handler *localICMPTestHandler) {
	require.Eventually(t, func() bool {
		return handler.judged.Load() == 1
	}, time.Second, time.Millisecond)
}

type localICMPTestIO struct {
	goPlatformIO
	packets [][]byte
}

func (p *localICMPTestIO) writeDatagram(packet []byte, _ ForwardFrameMeta) error {
	p.packets = append(p.packets, append([]byte(nil), packet...))
	return nil
}

func TestLocalICMPEchoBeforeFlowRouting(t *testing.T) {
	for _, stackName := range []string{"go", "system"} {
		for _, ipv6 := range []bool{false, true} {
			family := "IPv4"
			prefix := netip.MustParsePrefix("172.18.0.1/29")
			external := netip.MustParseAddr("8.8.8.8")
			if ipv6 {
				family = "IPv6"
				prefix = netip.MustParsePrefix("fdfe:dcba:9876::1/125")
				external = netip.MustParseAddr("2001:4860:4860::8888")
			}
			for _, test := range []struct {
				name        string
				destination netip.Addr
				customDNS   bool
				disabled    bool
				local       bool
			}{
				{"TUN address", prefix.Addr(), false, false, true},
				{"default DNS", prefix.Addr().Next(), false, false, true},
				{"custom DNS", prefix.Addr().Next().Next(), true, false, true},
				{"external DNS", external, true, false, false},
				{"disabled DNS", prefix.Addr().Next(), false, true, false},
				{"disabled custom DNS", prefix.Addr().Next().Next(), true, true, false},
				{"TUN address with DNS disabled", prefix.Addr(), false, true, true},
				{"ordinary destination", prefix.Addr().Next().Next(), false, false, false},
			} {
				t.Run(stackName+"/"+family+"/"+test.name, func(t *testing.T) {
					options := Options{AutoRoute: true}
					if ipv6 {
						options.Inet6Address = []netip.Prefix{prefix}
					} else {
						options.Inet4Address = []netip.Prefix{prefix}
					}
					if test.customDNS {
						options.DNSAddress = []netip.Addr{test.destination}
					}
					if test.disabled {
						options.DNSMode = DNSModeDisabled
					}
					source := prefix.Addr().Next().Next().Next()
					packet := buildICMPv4EchoPacket
					if ipv6 {
						packet = buildICMPv6EchoPacket
					}
					raw := packet(source, test.destination)
					handler := &localICMPTestHandler{}
					dispatcher := NewForwardDispatcher(handler, nil, nil, UDPNatOptions{}, 0)
					defer dispatcher.Close()
					stackOptions := StackOptions{TunOptions: options, Handler: handler}
					var replied bool
					if stackName == "go" {
						stackOptions.Tun = &MemoryTun{}
						stack, err := NewGo(stackOptions)
						require.NoError(t, err)
						platformIO := &localICMPTestIO{}
						engine := &goEngine{
							stack: stack, platformIO: platformIO,
							dispatchStage: dispatcher.NewStage(nil, func() {}),
						}
						buffer := buf.NewSize(32 + len(raw))
						defer buffer.Release()
						buffer.Resize(32, len(raw))
						copy(buffer.Bytes(), raw)
						engine.processFrame(&goFrame{buffer: buffer})
						replied = len(platformIO.packets) > 0
						if replied {
							require.Len(t, platformIO.packets, 1)
							raw = platformIO.packets[0]
						}
					} else {
						stack, err := NewSystem(stackOptions)
						require.NoError(t, err)
						system := stack.(*System)
						system.dispatchStage = dispatcher.NewStage(nil, func() {})
						replied = system.processPacket(raw)
					}
					require.Equal(t, test.local, replied)
					if !test.local {
						requireLocalICMPJudged(t, handler)
						return
					}
					require.Zero(t, handler.judged.Load())
					if ipv6 {
						ipHdr := header.IPv6(raw)
						icmpHdr := header.ICMPv6(ipHdr.Payload())
						require.Equal(t, test.destination, ipHdr.SourceAddr())
						require.Equal(t, source, ipHdr.DestinationAddr())
						require.Equal(t, header.ICMPv6EchoReply, icmpHdr.Type())
						require.Equal(t, header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
							Header: icmpHdr, Src: test.destination.AsSlice(), Dst: source.AsSlice(),
						}), icmpHdr.Checksum())
					} else {
						ipHdr := header.IPv4(raw)
						icmpHdr := header.ICMPv4(ipHdr.Payload())
						require.Equal(t, test.destination, ipHdr.SourceAddr())
						require.Equal(t, source, ipHdr.DestinationAddr())
						require.Equal(t, header.ICMPv4EchoReply, icmpHdr.Type())
						require.Equal(t, header.ICMPv4Checksum(icmpHdr, 0), icmpHdr.Checksum())
						require.Equal(t, ^ipHdr.CalculateChecksum(), ipHdr.Checksum())
					}
				})
			}
		}
	}
}

func TestGoLocalICMPErrorReachesSocket(t *testing.T) {
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("172.18.0.1/29"),
		netip.MustParsePrefix("fdfe:dcba:9876::1/125"),
	} {
		for _, address := range []netip.Addr{prefix.Addr(), prefix.Addr().Next()} {
			t.Run(address.String(), func(t *testing.T) {
				options := Options{AutoRoute: true}
				if address.Is4() {
					options.Inet4Address = []netip.Prefix{prefix}
				} else {
					options.Inet6Address = []netip.Prefix{prefix}
				}
				stack, err := NewGo(StackOptions{Tun: &MemoryTun{}, TunOptions: options})
				require.NoError(t, err)
				local := netip.AddrPortFrom(address, 40000)
				remote := netip.AddrPortFrom(prefix.Addr().Next().Next().Next(), 9000)
				socket := &GoUDPConn{local: local, remote: remote, connected: true, readSignal: make(goSignal, 1)}
				platformIO := &localICMPTestIO{}
				engine := &goEngine{
					stack: stack, platformIO: platformIO,
					udpSockets: map[netip.AddrPort]*GoUDPConn{local: socket},
				}
				// Quote an outbound UDP packet in an ICMP port-unreachable reply.
				ipVersion := goIPVersion(address)
				outgoing := make([]byte, goNetworkHeaderLength(ipVersion)+header.UDPMinimumSize)
				goEncodeUDPPacket(outgoing, ipVersion, local, remote, nil, 1)
				parsed, ok := parseForwardPacket(outgoing)
				require.True(t, ok)
				reply, ok := buildReject(&parsed, 0)
				require.True(t, ok)
				buffer := buf.As(reply)
				engine.processFrame(&goFrame{buffer: buffer})
				require.ErrorIs(t, socket.pendingErr, syscall.ECONNREFUSED)
				require.Empty(t, platformIO.packets)
			})
		}
	}
}

func TestSystemRespondsToDefaultIPv4DNSEcho(t *testing.T) {
	system := &System{}

	packet := buildICMPv4EchoPacket(netip.MustParseAddr("172.18.0.1"), netip.MustParseAddr("172.18.0.2"))
	ipHdr := header.IPv4(packet)
	icmpHdr := header.ICMPv4(ipHdr.Payload())

	writeBack, err := system.processIPv4ICMP(ipHdr, icmpHdr)
	require.NoError(t, err)
	require.True(t, writeBack)
	require.Equal(t, netip.MustParseAddr("172.18.0.2"), ipHdr.SourceAddr())
	require.Equal(t, netip.MustParseAddr("172.18.0.1"), ipHdr.DestinationAddr())
	require.Equal(t, header.ICMPv4EchoReply, icmpHdr.Type())
}

func TestSystemRespondsToDefaultIPv6DNSEcho(t *testing.T) {
	system := &System{}

	packet := buildICMPv6EchoPacket(netip.MustParseAddr("fdfe:dcba:9876::1"), netip.MustParseAddr("fdfe:dcba:9876::2"))
	ipHdr := header.IPv6(packet)
	icmpHdr := header.ICMPv6(ipHdr.Payload())

	writeBack, err := system.processIPv6ICMP(ipHdr, icmpHdr)
	require.NoError(t, err)
	require.True(t, writeBack)
	require.Equal(t, netip.MustParseAddr("fdfe:dcba:9876::2"), ipHdr.SourceAddr())
	require.Equal(t, netip.MustParseAddr("fdfe:dcba:9876::1"), ipHdr.DestinationAddr())
	require.Equal(t, header.ICMPv6EchoReply, icmpHdr.Type())
}

func TestLocalDNSServerAddresses(t *testing.T) {
	inet4Prefix := netip.MustParsePrefix("172.18.0.1/29")
	inet6Prefix := netip.MustParsePrefix("fdfe:dcba:9876::1/125")
	tests := []struct {
		name      string
		options   Options
		wantInet4 []netip.Addr
		wantInet6 []netip.Addr
	}{
		{
			name: "default disabled without auto route",
			options: Options{
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
			},
		},
		{
			name: "default",
			options: Options{
				AutoRoute:    true,
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
			},
			wantInet4: []netip.Addr{netip.MustParseAddr("172.18.0.2")},
			wantInet6: []netip.Addr{netip.MustParseAddr("fdfe:dcba:9876::2")},
		},
		{
			name: "custom addresses in TUN prefixes",
			options: Options{
				AutoRoute:    true,
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
				DNSAddress: []netip.Addr{
					netip.MustParseAddr("172.18.0.3"),
					netip.MustParseAddr("fdfe:dcba:9876::3"),
				},
			},
			wantInet4: []netip.Addr{netip.MustParseAddr("172.18.0.3")},
			wantInet6: []netip.Addr{netip.MustParseAddr("fdfe:dcba:9876::3")},
		},
		{
			name: "external custom addresses",
			options: Options{
				AutoRoute:    true,
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
				DNSAddress: []netip.Addr{
					netip.MustParseAddr("8.8.8.8"),
					netip.MustParseAddr("2001:4860:4860::8888"),
				},
			},
		},
		{
			name: "disabled",
			options: Options{
				AutoRoute:    true,
				Inet4Address: []netip.Prefix{inet4Prefix},
				Inet6Address: []netip.Prefix{inet6Prefix},
				DNSMode:      DNSModeDisabled,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inet4Addresses, inet6Addresses := localDNSServerAddresses(test.options)
			require.Equal(t, test.wantInet4, inet4Addresses)
			require.Equal(t, test.wantInet6, inet6Addresses)
		})
	}
}

func buildICMPv4EchoPacket(source netip.Addr, destination netip.Addr) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
		TTL:         64,
	})
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(1)
	icmpHdr.SetSequence(1)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return packet
}

func buildICMPv6EchoPacket(source netip.Addr, destination netip.Addr) []byte {
	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           source,
		DstAddr:           destination,
	})
	icmpHdr := header.ICMPv6(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv6EchoRequest)
	icmpHdr.SetIdent(1)
	icmpHdr.SetSequence(1)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    source.AsSlice(),
		Dst:    destination.AsSlice(),
	}))
	return packet
}
