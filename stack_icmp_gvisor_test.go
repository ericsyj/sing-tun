//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	gHdr "github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun/gtcpip/header"

	"github.com/stretchr/testify/require"
)

type localICMPTestTun struct {
	Tun
	endpoint *channel.Endpoint
}

func (t *localICMPTestTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, stack.NICOptions{}, nil
}

func (t *localICMPTestTun) WritePacket(*stack.PacketBuffer) (int, error) {
	panic("unexpected direct TUN write for local Echo or dropped packet")
}

func TestGVisorLocalICMPEchoBeforeFlowRouting(t *testing.T) {
	testLocalICMPEchoBeforeFlowRouting(t, func(t *testing.T, options Options, handler *localICMPTestHandler) func([]byte) []byte {
		endpoint := channel.New(16, 1500, "")
		t.Cleanup(endpoint.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		gvisor, err := NewGVisor(StackOptions{
			Context: ctx, Tun: &localICMPTestTun{endpoint: endpoint},
			TunOptions: options, Handler: handler,
			UDPTimeout: time.Minute, ICMPTimeout: time.Minute,
		})
		require.NoError(t, err)
		require.NoError(t, gvisor.Start())
		t.Cleanup(func() { require.NoError(t, gvisor.Close()) })
		return func(raw []byte) []byte {
			protocol := gHdr.IPv4ProtocolNumber
			if raw[0]>>4 == 6 {
				protocol = gHdr.IPv6ProtocolNumber
			}
			packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			endpoint.InjectInbound(protocol, packet)
			packet.DecRef()
			reply := endpoint.Read()
			if reply == nil {
				return nil
			}
			defer reply.DecRef()
			view := reply.ToView()
			defer view.Release()
			return append([]byte(nil), view.AsSlice()...)
		}
	})
}

func testLocalICMPEchoBeforeFlowRouting(t *testing.T, newStack func(*testing.T, Options, *localICMPTestHandler) func([]byte) []byte) {
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
			t.Run(family+"/"+test.name, func(t *testing.T) {
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
				process := newStack(t, options, handler)
				reply := process(raw)
				replied := reply != nil
				if replied {
					raw = reply
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
