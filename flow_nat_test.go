package tun

import (
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type selectorTestPort struct {
	Port
	count uint16
}

func (*selectorTestPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
}
func (*selectorTestPort) PortMTU() uint32 { return 1500 }
func (p *selectorTestPort) PortSelectorRanges(uint8) []SelectorRange {
	return []SelectorRange{{Start: 49152, Count: p.count}}
}
func (*selectorTestPort) ExpandSelectorRanges(uint8) bool { return false }
func (*selectorTestPort) AttachReturn(Return) error       { return nil }
func (*selectorTestPort) DetachReturn(Return) error       { return nil }

type selectorTestHandler struct {
	Handler
	port Port
}

func (h *selectorTestHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionFlow, Port: h.port}
}

type selectorTestWriteback struct{ ForwardWriteback }

func (*selectorTestWriteback) ReturnHeadroom() int { return 0 }

func selectorTestDispatcher(t *testing.T, count uint16) (*ForwardDispatcher, *selectorTestPort) {
	t.Helper()
	port := &selectorTestPort{count: count}
	d := NewForwardDispatcher(&selectorTestHandler{port: port}, &selectorTestWriteback{}, logger.NOP(), UDPNatOptions{Timeout: time.Minute}, time.Minute)
	t.Cleanup(d.Close)
	return d, port
}

func selectorTestStage(d *ForwardDispatcher) *ForwardStage {
	return d.NewStage(nil, func() {})
}

func selectorTestPacket(source string) forwardPacket {
	packet := forwardPacket{ipVersion: 4, protocol: uint8(header.TCPProtocolNumber), source: netip.MustParseAddrPort(source), destination: netip.MustParseAddrPort("198.51.100.1:443"), hasFlow: true, tcpFlags: header.TCPFlagSyn}
	if packet.source.Addr().Is6() {
		packet.ipVersion = 6
		packet.destination = netip.MustParseAddrPort("[2001:db8:2::1]:443")
	}
	return packet
}

func selectorTestInstall(t *testing.T, stage *ForwardStage, source string) *flowEntry {
	t.Helper()
	packet := selectorTestPacket(source)
	var raw []byte
	var tcp header.TCP
	if packet.ipVersion == 4 {
		raw = make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
		ip := header.IPv4(raw)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(raw)), Protocol: uint8(header.TCPProtocolNumber), TTL: 64, SrcAddr: packet.source.Addr(), DstAddr: packet.destination.Addr()})
		tcp = header.TCP(ip.Payload())
	} else {
		raw = make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
		ip := header.IPv6(raw)
		ip.Encode(&header.IPv6Fields{PayloadLength: header.TCPMinimumSize, TransportProtocol: header.TCPProtocolNumber, HopLimit: 64, SrcAddr: packet.source.Addr(), DstAddr: packet.destination.Addr()})
		tcp = header.TCP(ip.Payload())
	}
	tcp.Encode(&header.TCPFields{SrcPort: packet.source.Port(), DstPort: packet.destination.Port(), SeqNum: 1, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535})
	key := packet.flowKey()
	require.True(t, stage.Dispatch(raw))
	// Flow judgment runs asynchronously; install the verdict once it is ready.
	require.Eventually(t, func() bool {
		stage.access.Lock()
		defer stage.access.Unlock()
		return len(stage.judged) > 0
	}, time.Second, time.Millisecond)
	stage.ResumeJudged(func([]byte, ForwardFrameMeta) {})
	stage.access.Lock()
	defer stage.access.Unlock()
	return stage.table[key]
}

func TestForwardNATReclaimsOnExhaustion(t *testing.T) {
	for _, sources := range [][2]string{{"10.0.0.1:49152", "10.0.0.2:49152"}, {"[2001:db8:1::1]:49152", "[2001:db8:1::2]:49152"}} {
		for _, state := range []string{"expired", "aborted", "closed", "tombstone", "active", "reverse active"} {
			t.Run(sources[0]+"/"+state, func(t *testing.T) {
				d, _ := selectorTestDispatcher(t, 1)
				oldStage, newStage := selectorTestStage(d), selectorTestStage(d)
				old := selectorTestInstall(t, oldStage, sources[0])
				require.Equal(t, ActionFlow, old.action)
				oldFlow := old.flow
				oldPacket := selectorTestPacket(sources[0])
				key := oldPacket.flowKey()
				switch state {
				case "expired":
					old.deadline = -1
				case "aborted":
					old.flow.CloseFlow()
				case "closed":
					old.flow.close(FlowCloseReset)
				case "tombstone":
					old.flow.close(FlowCloseReset)
					oldStage.sweep(d.now())
					require.Equal(t, ActionDrop, old.action)
				case "reverse active":
					old.deadline = -1
					old.flow.lastReverse.Store(d.now())
				}
				current := selectorTestInstall(t, newStage, sources[1])
				if state == "active" || state == "reverse active" {
					require.Nil(t, current)
					require.Len(t, newStage.writebackBatch, 1)
					require.Same(t, oldFlow, oldFlow.nat.lookup(oldFlow.reverseKey))
					require.False(t, oldFlow.closed.Load())
					return
				}
				require.NotNil(t, current, "reclaim unusable mappings before rejecting a new flow")
				require.Equal(t, ActionFlow, current.action)
				require.Same(t, current.flow, oldFlow.nat.lookup(oldFlow.reverseKey))
				if state == "closed" || state == "tombstone" {
					entry := oldStage.table[key]
					require.NotNil(t, entry, "reclaim must preserve the forward tombstone")
					require.Equal(t, ActionDrop, entry.action)
					require.Nil(t, entry.flow)
				}
				// Cleanup of the old forward entry must not remove the replacement mapping.
				if entry := oldStage.table[key]; entry != nil {
					oldStage.removeEntry(key, entry, FlowCloseTimeout)
				}
				require.Same(t, current.flow, oldFlow.nat.lookup(oldFlow.reverseKey))
			})
		}
	}
}

func TestForwardNATRetriesAfterCapacityReturns(t *testing.T) {
	d, _ := selectorTestDispatcher(t, 1)
	oldStage, newStage := selectorTestStage(d), selectorTestStage(d)
	old := selectorTestInstall(t, oldStage, "10.0.0.1:49152")
	require.Nil(t, selectorTestInstall(t, newStage, "10.0.0.2:49152"))
	require.Len(t, newStage.writebackBatch, 1, "a full pool must reject the new SYN")
	old.flow.CloseFlow()
	retried := selectorTestInstall(t, newStage, "10.0.0.2:49152")
	require.NotNil(t, retried, "temporary capacity failure must not cache a route rejection")
	require.Equal(t, ActionFlow, retried.action)
}

func TestForwardNATKeepsClosedMappingWhileCapacityAvailable(t *testing.T) {
	d, _ := selectorTestDispatcher(t, 2)
	stage := selectorTestStage(d)
	old := selectorTestInstall(t, stage, "10.0.0.1:49152")
	old.flow.close(FlowCloseReset)
	current := selectorTestInstall(t, stage, "10.0.0.2:49152")
	require.Equal(t, ActionFlow, current.action)
	require.NotEqual(t, old.flow.reverseKey, current.flow.reverseKey)
	require.Same(t, old.flow, old.flow.nat.lookup(old.flow.reverseKey))
}

func TestForwardNATConcurrentExhaustionAcrossStages(t *testing.T) {
	d, port := selectorTestDispatcher(t, 2)
	stages := make([]*ForwardStage, 4)
	for i := range stages {
		stages[i] = selectorTestStage(d)
	}
	var wg sync.WaitGroup
	for i, stage := range stages {
		wg.Go(func() {
			address := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
			for j := range 100 {
				source := netip.AddrPortFrom(address, uint16(49152+j)).String()
				selectorTestInstall(t, stage, source)
				packet := selectorTestPacket(source)
				stage.access.Lock()
				if entry := stage.table[packet.flowKey()]; entry != nil && entry.flow != nil {
					entry.flow.close(FlowCloseReset)
				}
				stage.access.Unlock()
			}
		})
	}
	wg.Wait()
	nat := d.natFor(port)
	for i := range nat.shards {
		for _, flow := range nat.shards[i].flows {
			require.NotNil(t, flow, "no unpublished reservation should remain")
		}
	}
}

type reservationTestPort struct {
	selectorTestPort
	reserved map[netip.AddrPort]bool
	releases int
}

func (p *reservationTestPort) ReserveSelector(_ uint8, address netip.AddrPort) bool {
	if p.reserved[address] {
		return false
	}
	p.reserved[address] = true
	return true
}

func (p *reservationTestPort) ReleaseSelector(_ uint8, address netip.AddrPort) {
	delete(p.reserved, address)
	p.releases++
}

func TestForwardNATReclaimSharedSelector(t *testing.T) {
	for _, protocol := range []uint8{uint8(header.TCPProtocolNumber), uint8(header.UDPProtocolNumber)} {
		for _, source := range []string{"10.0.0.1:49152", "[2001:db8:1::1]:49152"} {
			for _, state := range []string{"closed", "aborted", "expired"} {
				t.Run(netip.MustParseAddrPort(source).String()+"/"+strconv.Itoa(int(protocol))+"/"+state, func(t *testing.T) {
					port := &reservationTestPort{selectorTestPort: selectorTestPort{count: 1}, reserved: make(map[netip.AddrPort]bool)}
					d := NewForwardDispatcher(&selectorTestHandler{port: port}, &selectorTestWriteback{}, logger.NOP(), UDPNatOptions{Timeout: time.Minute}, time.Minute)
					t.Cleanup(d.Close)
					firstStage, secondStage := selectorTestStage(d), selectorTestStage(d)
					firstPacket := selectorTestPacket(source)
					firstPacket.protocol = protocol
					secondPacket := firstPacket
					secondPacket.destination = netip.AddrPortFrom(firstPacket.destination.Addr().Next(), 443)
					install := func(stage *ForwardStage, packet *forwardPacket) *forwardFlow {
						flow, result := stage.createFlow(packet, FlowVerdict{Action: ActionFlow, Port: port})
						require.Equal(t, createFlowOK, result)
						stage.table[packet.flowKey()] = &flowEntry{action: ActionFlow, flow: flow, idle: time.Minute, deadline: d.now() + int64(time.Minute)}
						return flow
					}
					first := install(firstStage, &firstPacket)
					second := install(secondStage, &secondPacket)
					require.Equal(t, first.selectorKey, second.selectorKey)
					if protocol == uint8(header.UDPProtocolNumber) {
						require.Same(t, first.mapping, second.mapping)
					}
					switch state {
					case "closed":
						first.close(FlowCloseReset)
					case "aborted":
						first.CloseFlow()
					default:
						firstStage.table[firstPacket.flowKey()].deadline = -1
					}
					d.reclaimNAT(port)
					require.Nil(t, first.nat.lookup(first.reverseKey))
					require.Same(t, second, second.nat.lookup(second.reverseKey))
					require.Len(t, port.reserved, 1)
					require.Zero(t, port.releases, "a shared selector must stay reserved while a flow is live")
					if protocol == uint8(header.UDPProtocolNumber) {
						require.Equal(t, []*forwardFlow{second}, second.mapping.flows)
						require.Same(t, second, second.mapping.anchor)
					}
					second.CloseFlow()
					d.reclaimNAT(port)
					require.Empty(t, port.reserved)
					require.Equal(t, 1, port.releases)
					require.Empty(t, first.nat.selectors)
					require.Empty(t, first.nat.mappings)
					replacement := install(secondStage, &secondPacket)
					d.reclaimNAT(port)
					if entry := firstStage.table[firstPacket.flowKey()]; entry != nil {
						require.Equal(t, ActionDrop, entry.action)
						firstStage.removeEntry(firstPacket.flowKey(), entry, FlowCloseTimeout)
					}
					require.Same(t, replacement, replacement.nat.lookup(replacement.reverseKey))
					require.Len(t, port.reserved, 1)
					require.Equal(t, 1, port.releases, "old tombstone cleanup must not release a replacement selector")
				})
			}
		}
	}
}
