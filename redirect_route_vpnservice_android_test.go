package tun

import (
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

const (
	vpnServiceTestLocalNetworkTable = "97"
	vpnServiceTestCellularTable     = "1020"
	vpnServiceTestWiFiTable         = "1030"
	vpnServiceTestHotspotTable      = "1085"
	vpnServiceTestClient            = "10.65.121.68"
	vpnServiceTestRemote            = "1.1.1.1"
	vpnServiceTestOutputMark        = "0x200000"
	vpnServiceTestResetMark         = "0x600000"
)

// Run on Linux with SING_TUN_TEST_IPTABLES=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN,
// using a binary built with GOOS=android CGO_ENABLED=0 go test -c and
// /system/bin/linker64 linked to the host's dynamic loader.
// Each case runs in its own network namespace, leaving host rules untouched.
func TestAndroidVPNServiceLocalNetworkRoutes(t *testing.T) {
	if os.Getenv("SING_TUN_TEST_IPTABLES") != "1" {
		t.Skip("requires iproute2 and network namespace privileges")
	}
	if scenario := os.Getenv("SING_TUN_TEST_IPTABLES_CASE"); scenario != "" {
		testAndroidVPNServiceLocalNetworkRoutes(t, scenario)
		return
	}
	for _, scenario := range []string{"hotspot-first", "hotspot-later", "default-network-change", "shared-table", "stale-rules", "bypass-route"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestAndroidVPNServiceLocalNetworkRoutes$", "-test.v")
			command.Env = append(os.Environ(), "SING_TUN_TEST_IPTABLES_CASE="+scenario)
			command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated route test: %v\n%s", err, output)
			}
		})
	}
}

type vpnServiceRouteTest struct {
	t *testing.T
	r *autoRedirect
}

func (s *vpnServiceRouteTest) ip(args ...string) string {
	s.t.Helper()
	output, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		s.t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func (s *vpnServiceRouteTest) setup() {
	s.t.Helper()
	s.ip("link", "set", "lo", "up")
	for _, name := range []string{"tun0", "rmnet0", "wlan0", "wlan2"} {
		s.ip("link", "add", name, "type", "dummy")
		s.ip("link", "set", name, "up")
	}
	s.ip("addr", "add", "172.18.0.1/30", "dev", "tun0")
	s.ip("addr", "add", "10.83.209.179/29", "dev", "rmnet0")
	s.ip("addr", "add", "192.168.50.2/24", "dev", "wlan0")
	s.ip("addr", "add", "10.65.121.63/24", "dev", "wlan2")
	tunLink, err := netlink.LinkByName("tun0")
	if err != nil {
		s.t.Fatal(err)
	}
	tunTable := strconv.Itoa(tunLink.Attrs().Index + androidRouteTableOffsetFromIndex)
	s.ip("route", "add", "0.0.0.0/1", "dev", "tun0", "table", tunTable)
	s.ip("route", "add", "128.0.0.0/1", "dev", "tun0", "table", tunTable)
	s.ip("route", "add", "default", "via", "10.83.209.180", "dev", "rmnet0", "table", vpnServiceTestCellularTable)
	s.ip("route", "add", "default", "via", "192.168.50.1", "dev", "wlan0", "table", vpnServiceTestWiFiTable)
	s.ip("rule", "add", "pref", "12000", "iif", "tun0", "lookup", vpnServiceTestLocalNetworkTable)
	s.ip("rule", "add", "pref", "13000", "fwmark", "0x0/0x20000", "iif", "lo", "uidrange", "0-99999", "lookup", tunTable)
	s.ip("rule", "add", "pref", "20000", "fwmark", "0x0/0x10000", "lookup", vpnServiceTestLocalNetworkTable)
	s.ip("rule", "add", "pref", "31000", "fwmark", "0x0/0xffff", "iif", "lo", "lookup", vpnServiceTestCellularTable)
	s.r = &autoRedirect{
		tunOptions: &Options{
			Name:                   "tun0",
			Inet4Address:           []netip.Prefix{netip.MustParsePrefix("172.18.0.1/30")},
			AutoRedirectInputMark:  DefaultAutoRedirectInputMarkAndroid,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMarkAndroid,
			AutoRedirectResetMark:  DefaultAutoRedirectResetMarkAndroid,
			AutoRedirectTProxyMark: DefaultAutoRedirectTProxyMarkAndroid,
		},
		logger:     logger.NOP(),
		enableIPv4: true,
	}
}

func (s *vpnServiceRouteTest) hotspot(action string) {
	s.t.Helper()
	s.ip("route", action, "10.65.121.0/24", "dev", "wlan2", "table", vpnServiceTestHotspotTable)
	s.ip("rule", action, "pref", "20000", "fwmark", "0x0/0x10000", "lookup", vpnServiceTestHotspotTable)
}

func (s *vpnServiceRouteTest) update() {
	s.t.Helper()
	err := s.r.updateAndroidVPNServiceRules()
	if err != nil {
		s.t.Fatal(err)
	}
}

func (s *vpnServiceRouteTest) expectDevice(destination string, mark string, device string) {
	s.t.Helper()
	args := []string{"route", "get", destination}
	if mark != "" {
		args = append(args, "mark", mark)
	}
	output := s.ip(args...)
	if !strings.Contains(output, " dev "+device+" ") {
		s.t.Fatalf("%s with mark %q: expected dev %s, got %s\nrules:\n%s", destination, mark, device, output, s.ip("rule", "show"))
	}
}

func (s *vpnServiceRouteTest) serviceRules() []string {
	s.t.Helper()
	var rules []string
	for line := range strings.SplitSeq(s.ip("rule", "show"), "\n") {
		if strings.HasPrefix(line, "8999:") || strings.HasPrefix(line, "9000:") {
			rules = append(rules, line)
		}
	}
	return rules
}

func testAndroidVPNServiceLocalNetworkRoutes(t *testing.T, scenario string) {
	s := &vpnServiceRouteTest{t: t}
	s.setup()
	switch scenario {
	case "hotspot-first":
		s.hotspot("add")
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestResetMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.r.cleanupAndroidVPNServiceRules()
		if rules := s.serviceRules(); len(rules) != 0 {
			t.Fatalf("rules left after cleanup: %q", rules)
		}
	case "hotspot-later":
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.hotspot("add")
		s.update()
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestResetMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		rules := s.serviceRules()
		s.update()
		if repeated := s.serviceRules(); strings.Join(repeated, "\n") != strings.Join(rules, "\n") {
			t.Fatalf("repeated update changed rules:\n%q\n%q", rules, repeated)
		}
		s.hotspot("del")
		s.update()
		for _, rule := range s.serviceRules() {
			if strings.Contains(rule, "lookup "+vpnServiceTestHotspotTable) {
				t.Fatalf("hotspot rule left after the network went away: %q", rule)
			}
		}
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.r.cleanupAndroidVPNServiceRules()
		if rules = s.serviceRules(); len(rules) != 0 {
			t.Fatalf("rules left after cleanup: %q", rules)
		}
	case "default-network-change":
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.hotspot("add")
		s.update()
		s.ip("rule", "del", "pref", "31000", "fwmark", "0x0/0xffff", "iif", "lo", "lookup", vpnServiceTestCellularTable)
		s.ip("rule", "add", "pref", "31000", "fwmark", "0x0/0xffff", "iif", "lo", "lookup", vpnServiceTestWiFiTable)
		s.update()
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "wlan0")
		s.r.cleanupAndroidVPNServiceRules()
	case "shared-table":
		s.ip("route", "add", "10.65.121.0/24", "dev", "wlan2", "table", vpnServiceTestLocalNetworkTable)
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestClient, vpnServiceTestOutputMark, "wlan2")
		s.expectDevice(vpnServiceTestClient, vpnServiceTestResetMark, "wlan2")
		s.expectDevice(vpnServiceTestRemote, vpnServiceTestOutputMark, "rmnet0")
		s.r.cleanupAndroidVPNServiceRules()
	case "stale-rules":
		// Left by a process that died with other networks available, so
		// neither rule is installed again and only the stale pass removes them.
		s.ip("rule", "add", "pref", "8999", "fwmark", vpnServiceTestOutputMark+"/0xe00000", "iif", "lo", "lookup", vpnServiceTestHotspotTable)
		s.ip("rule", "add", "pref", "9000", "fwmark", vpnServiceTestOutputMark+"/0xe00000", "iif", "lo", "lookup", vpnServiceTestWiFiTable)
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		for _, rule := range s.serviceRules() {
			if strings.Contains(rule, "lookup "+vpnServiceTestHotspotTable) || strings.Contains(rule, "lookup "+vpnServiceTestWiFiTable) {
				t.Fatalf("stale rule left after setup: %q", rule)
			}
		}
		s.r.cleanupAndroidVPNServiceRules()
		if rules := s.serviceRules(); len(rules) != 0 {
			t.Fatalf("rules left after cleanup: %q", rules)
		}
	case "bypass-route":
		s.r.routeAddressSet = func() ([]netip.Prefix, []netip.Prefix, error) {
			return nil, []netip.Prefix{netip.MustParsePrefix("10.65.121.0/24"), netip.MustParsePrefix(vpnServiceTestRemote + "/32")}, nil
		}
		if err := s.r.setupAndroidVPNServiceRules(); err != nil {
			t.Fatal(err)
		}
		s.r.setupBypassRoute()
		if !s.r.bypassRouteActive {
			t.Fatal("bypass route is not active")
		}
		s.expectDevice(vpnServiceTestRemote, "", "rmnet0")
		s.hotspot("add")
		if err := s.r.updateBypassRoute(); err != nil {
			t.Fatal(err)
		}
		s.expectDevice(vpnServiceTestClient, "", "wlan2")
		s.expectDevice(vpnServiceTestRemote, "", "rmnet0")
		s.r.cleanupBypassRoute()
		s.r.cleanupAndroidVPNServiceRules()
	default:
		t.Fatalf("unknown scenario %q", scenario)
	}
}
