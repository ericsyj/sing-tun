//go:build linux && !android

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/unix"
)

// Run with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN.
// Each case runs in its own network namespace, leaving host rules untouched.
func TestAndroidVPNBypassNAT(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires iptables, iproute2 and network namespace privileges")
	}
	if scenario := os.Getenv("SING_TUN_TEST_IPTABLES_CASE"); scenario != "" {
		testAndroidVPNBypassNAT(t, scenario)
		return
	}
	for _, scenario := range []string{"unchanged", "clear", "qos", "unmarked", "outside-prefix", "tun-output"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestAndroidVPNBypassNAT$", "-test.v")
			command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_CASE="+scenario)
			command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated NAT test: %v\n%s", err, output)
			}
		})
	}
}

func TestIsRedirectLocalAddress(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		interfaceName string
		address       string
		expected      bool
	}{
		{"wlan0", "192.168.1.2", true},
		{"wlan0", "2001:db8::1", true},
		{"wlan0", "fd00::1", true},
		{"wlan0", "fe80::1", true},
		{"wlan0", "169.254.1.1", false},
		{"wlan0", "ff02::1", false},
		{"lo", "127.0.0.1", true},
		{"lo", "::1", true},
	} {
		address := netip.MustParseAddr(testCase.address)
		if actual := isRedirectLocalAddress(testCase.interfaceName, address); actual != testCase.expected {
			t.Errorf("isRedirectLocalAddress(%q, %s) = %v, want %v", testCase.interfaceName, address, actual, testCase.expected)
		}
	}
}

// Run with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN.
// The redirect port has no listener, so an intercepted packet is dropped by TPROXY.
func TestIPTablesTProxyLinkLocal(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires ip6tables, iproute2 and network namespace privileges")
	}
	if scenario := os.Getenv("SING_TUN_TEST_IPTABLES_CASE"); scenario != "" {
		testIPTablesTProxyLinkLocal(t, scenario)
		return
	}
	for _, scenario := range []string{"outbound", "inbound", "stale-outbound"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestIPTablesTProxyLinkLocal$", "-test.v")
			command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_CASE="+scenario)
			command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated TPROXY test: %v\n%s", err, output)
			}
		})
	}
}

func testIPTablesTProxyLinkLocal(t *testing.T, scenario string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
	}
	peer := "sing-tun-test-" + scenario
	run("ip", "netns", "add", peer)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "delete", peer).Run()
	})
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "vpn0", "type", "dummy")
	run("ip", "link", "set", "vpn0", "up")
	run("ip", "link", "add", "local0", "type", "veth", "peer", "name", "peer0", "netns", peer)
	run("ip", "addr", "add", "fe80::1/64", "dev", "local0", "nodad")
	run("ip", "link", "set", "local0", "up")
	run("ip", "-n", peer, "addr", "add", "fe80::2/64", "dev", "peer0", "nodad")
	run("ip", "-n", peer, "link", "set", "peer0", "up")

	redirect := &autoRedirect{
		tunOptions: &Options{
			Name: "vpn0", Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			AutoRedirectInputMark: 0x400000, AutoRedirectOutputMark: 0x200000,
			AutoRedirectResetMark: 0x600000, AutoRedirectTProxyMark: 0x800000,
		},
		androidVPNService: true, tableName: "tp-test", customRedirectPort: 12345,
		interfaceFinder: control.NewDefaultInterfaceFinder(),
	}
	if scenario != "stale-outbound" {
		localAddresses, err := redirect.findLocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		redirect.localAddresses = localAddresses
	}
	if err := redirect.setupIPTablesForFamily(&iptablesFamily{path: "ip6tables", isIPv6: true, tproxy: true}); err != nil {
		t.Fatal(err)
	}

	var (
		listenAddress = "[fe80::2%peer0]:43210"
		dialAddress   = "[fe80::2%local0]:43210"
		listenIn      = peer
		dialIn        = ""
	)
	if scenario == "inbound" {
		listenAddress, dialAddress = "[fe80::1%local0]:43210", "[fe80::1%peer0]:43210"
		listenIn, dialIn = "", peer
	}
	inNamespace := func(name string, block func() error) error {
		if name == "" {
			return block()
		}
		return runInNetworkNamespace(name, block)
	}
	var listener net.Listener
	err := inNamespace(listenIn, func() (err error) {
		listener, err = net.Listen("tcp6", listenAddress)
		return
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	var conn net.Conn
	err = inNamespace(dialIn, func() (err error) {
		conn, err = net.DialTimeout("tcp6", dialAddress, 3*time.Second)
		return
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("link-local")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, echoed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echoed %q, want %q", echoed, payload)
	}
}

func testAndroidVPNBypassNAT(t *testing.T, scenario string) {
	t.Helper()
	run := func(name string, args ...string) {
		t.Helper()
		if output, err := exec.Command(name, args...).CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, output)
		}
	}
	run("ip", "link", "set", "lo", "up")
	for _, device := range []struct{ name, address string }{{"vpn0", "172.19.0.1/30"}, {"cell0", "192.0.2.1/24"}} {
		run("ip", "link", "add", device.name, "type", "dummy")
		run("ip", "addr", "add", device.address, "dev", device.name)
		run("ip", "link", "set", device.name, "up")
	}
	outputInterface := "cell0"
	if scenario == "tun-output" {
		outputInterface = "vpn0"
		run("ip", "route", "add", "192.0.2.2/32", "dev", outputInterface)
	}
	redirect := &autoRedirect{
		tunOptions: &Options{
			Name: "vpn0", Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
			AutoRedirectInputMark: 0x400000, AutoRedirectOutputMark: 0x200000, AutoRedirectResetMark: 0x600000,
		},
		androidVPNService: true, tableName: "nat-test", customRedirectPort: 12345,
	}
	if err := redirect.setupIPTablesForFamily(&iptablesFamily{path: "iptables"}); err != nil {
		t.Fatal(err)
	}
	// Isolate source NAT from interception. Populate the connection mark as
	// pre-match does, then simulate the vendor's later packet-mark rewrite.
	run("iptables", "-t", "nat", "-F", "OUTPUT")
	run("iptables", "-t", "mangle", "-F", "OUTPUT")
	if scenario != "unmarked" {
		run("iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "MARK", "--set-xmark", "0x200000/0xe00000")
		run("iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "CONNMARK", "--save-mark", "--nfmask", "0xe00000", "--ctmask", "0xe00000")
	}
	if scenario != "unchanged" {
		mark := "0x13a/0xffffffff"
		if scenario == "clear" {
			mark = "0x0/0xffffffff"
		}
		run("iptables", "-t", "mangle", "-A", "POSTROUTING", "-j", "MARK", "--set-xmark", mark)
	}
	device, err := net.InterfaceByName(outputInterface)
	if err != nil {
		t.Fatal(err)
	}
	// AF_PACKET observes the actual outgoing IPv4 header after source NAT.
	protocol := int(binary.NativeEndian.Uint16([]byte{0x00, unix.ETH_P_ALL}))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(protocol), Ifindex: device.Index}); err != nil {
		t.Fatal(err)
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3}); err != nil {
		t.Fatal(err)
	}
	source := net.ParseIP("172.19.0.1")
	expected := net.ParseIP("192.0.2.1")
	switch scenario {
	case "outside-prefix":
		run("ip", "addr", "add", "198.51.100.1/32", "dev", "vpn0")
		source = net.ParseIP("198.51.100.1")
		expected = source
	case "unmarked", "tun-output":
		expected = source
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: source}, &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 43210})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("android-vpn-bypass-nat")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 2048)
	for {
		n, _, readErr := unix.Recvfrom(fd, packet, 0)
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			t.Fatalf("capture outgoing packet: %v", readErr)
		}
		if n < 28 || packet[0]>>4 != 4 || !bytes.HasSuffix(packet[:n], payload) {
			continue
		}
		if actual := net.IP(packet[12:16]); !actual.Equal(expected) {
			t.Fatalf("outgoing source = %s, want %s", actual, expected)
		}
		return
	}
}
