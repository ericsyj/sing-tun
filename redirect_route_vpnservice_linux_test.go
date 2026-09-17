//go:build linux

package tun

import (
	"reflect"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

func TestDiscoverAndroidVPNServiceTables(t *testing.T) {
	t.Parallel()
	const (
		localNetworkTable = 97
		legacyNetwork     = 98
		legacySystem      = 99
		cellularTable     = 1020
		cellularLocal     = 1000000020
		clatTable         = 1021
		hotspotTable      = 1085
		usbTable          = 1086
		tunTable          = 1088
	)
	uidRange := netlink.NewRuleUIDRange(0, 10097)
	localNetworkRule := func(table int) netlink.Rule {
		return netlink.Rule{Priority: androidLocalNetworkRulePriority, Mask: androidExplicitSelectMask, Table: table}
	}
	for _, testCase := range []struct {
		name     string
		rules    []netlink.Rule
		expected androidVPNServiceTables
	}{
		{name: "no rules"},
		{
			name: "per-interface tethering table",
			rules: []netlink.Rule{
				{Priority: 12000, IifName: "tun0", Table: localNetworkTable},
				{Priority: 13000, Mask: androidSecureVPNMask, IifName: "lo", UIDRange: uidRange, Table: tunTable},
				localNetworkRule(localNetworkTable),
				localNetworkRule(hotspotTable),
				{Priority: 21000, IifName: "wlan2", Table: cellularTable},
				{Priority: 25000, Mask: androidExplicitSelectMask, IifName: "lo", UIDRange: uidRange, Table: cellularLocal},
				{Priority: 26000, Mask: androidExplicitSelectMask, IifName: "lo", Table: cellularLocal},
				{Priority: 29040, Mask: androidNetIDMask, IifName: "lo", UIDRange: uidRange, Table: cellularTable},
				{Priority: 31000, Mask: androidNetIDMask, IifName: "lo", Table: cellularTable},
			},
			expected: androidVPNServiceTables{physical: []int{cellularTable}, localNetworks: []int{localNetworkTable, hotspotTable}},
		},
		{
			name: "multiple downstreams",
			rules: []netlink.Rule{
				localNetworkRule(localNetworkTable),
				localNetworkRule(hotspotTable),
				localNetworkRule(usbTable),
				localNetworkRule(hotspotTable),
			},
			expected: androidVPNServiceTables{localNetworks: []int{localNetworkTable, hotspotTable, usbTable}},
		},
		{
			name: "legacy tables stay out",
			rules: []netlink.Rule{
				{Priority: 12000, IifName: "tun0", Table: localNetworkTable},
				{Priority: 18000, Mask: androidExplicitSelectMask, Table: legacySystem},
				{Priority: 19000, Mask: androidExplicitSelectMask, Table: legacyNetwork},
				localNetworkRule(localNetworkTable),
				{Priority: 31000, Mask: androidNetIDMask, IifName: "lo", Table: cellularTable},
				{Priority: 31000, Mask: androidNetIDMask, IifName: "lo", Table: clatTable},
			},
			expected: androidVPNServiceTables{physical: []int{cellularTable, clatTable}, localNetworks: []int{localNetworkTable}},
		},
		{
			name: "vpn rule at an unexpected priority",
			rules: []netlink.Rule{
				{Priority: 12500, IifName: "tun0", Table: localNetworkTable},
				{Priority: 12501, IifName: "tun0", Table: tunTable},
			},
			expected: androidVPNServiceTables{localNetworks: []int{localNetworkTable}},
		},
		{
			name: "other vpn interface",
			rules: []netlink.Rule{
				{Priority: 12000, IifName: "tun1", Table: localNetworkTable},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			actual := discoverAndroidVPNServiceTables(testCase.rules, "tun0")
			if !reflect.DeepEqual(actual, testCase.expected) {
				t.Fatalf("got %+v, want %+v", actual, testCase.expected)
			}
		})
	}
}

func TestAndroidVPNServiceFamilyRules(t *testing.T) {
	t.Parallel()
	type ruleSummary struct {
		priority int
		mark     uint32
		iif      string
		table    int
	}
	const (
		inputMark  = DefaultAutoRedirectInputMarkAndroid
		outputMark = DefaultAutoRedirectOutputMarkAndroid
		resetMark  = DefaultAutoRedirectResetMarkAndroid
		tproxyMark = DefaultAutoRedirectTProxyMarkAndroid
		vpnTable   = 1088
	)
	tables := androidVPNServiceTables{physical: []int{1020, 1021}, localNetworks: []int{97, 1085}}
	for _, testCase := range []struct {
		name      string
		family    int
		ruleIndex int
		tables    androidVPNServiceTables
		expected  []ruleSummary
	}{
		{
			name:   "ipv4",
			family: unix.AF_INET,
			tables: tables,
			expected: []ruleSummary{
				{9000, inputMark, "", vpnTable},
				{9000, resetMark, "", 97},
				{9000, resetMark, "", 1085},
				{8999, outputMark, "lo", 97},
				{8999, outputMark, "lo", 1085},
				{9000, outputMark, "lo", 1020},
				{9000, outputMark, "lo", 1021},
			},
		},
		{
			name:   "ipv6 skips output rules",
			family: unix.AF_INET6,
			tables: tables,
			expected: []ruleSummary{
				{9000, inputMark, "", vpnTable},
				{9000, resetMark, "", 97},
				{9000, resetMark, "", 1085},
			},
		},
		{
			name:      "custom rule index",
			family:    unix.AF_INET,
			ruleIndex: 5000,
			tables:    androidVPNServiceTables{physical: []int{1020}, localNetworks: []int{1085}},
			expected: []ruleSummary{
				{5000, inputMark, "", vpnTable},
				{5000, resetMark, "", 1085},
				{4999, outputMark, "lo", 1085},
				{5000, outputMark, "lo", 1020},
			},
		},
		{
			name:   "no local network",
			family: unix.AF_INET,
			tables: androidVPNServiceTables{physical: []int{1020}},
			expected: []ruleSummary{
				{9000, inputMark, "", vpnTable},
				{9000, outputMark, "lo", 1020},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			r := &autoRedirect{tunOptions: &Options{
				IPRoute2RuleIndex:      testCase.ruleIndex,
				AutoRedirectInputMark:  inputMark,
				AutoRedirectOutputMark: outputMark,
				AutoRedirectResetMark:  resetMark,
				AutoRedirectTProxyMark: tproxyMark,
			}}
			var actual []ruleSummary
			for _, rule := range r.androidVPNServiceFamilyRules(testCase.family, vpnTable, testCase.tables) {
				if rule.Family != testCase.family || !rule.MarkSet || rule.Mask != inputMark|outputMark|resetMark|tproxyMark {
					t.Fatalf("unexpected rule attributes: %+v", rule)
				}
				actual = append(actual, ruleSummary{rule.Priority, rule.Mark, rule.IifName, rule.Table})
			}
			if !reflect.DeepEqual(actual, testCase.expected) {
				t.Fatalf("got %+v, want %+v", actual, testCase.expected)
			}
		})
	}
}
