package tun

import (
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (r *autoRedirect) discoverAndroidVPNServiceRules() ([]*netlink.Rule, error) {
	tunLink, err := netlink.LinkByName(r.tunOptions.Name)
	if err != nil {
		return nil, E.Cause(err, "find tun interface")
	}
	vpnTable := tunLink.Attrs().Index + androidRouteTableOffsetFromIndex
	var (
		rules    []*netlink.Rule
		ruleList []netlink.Rule
	)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		familyName := "ipv4"
		if family == unix.AF_INET6 {
			if !r.enableIPv6 {
				continue
			}
			familyName = "ipv6"
		} else if !r.enableIPv4 {
			continue
		}
		ruleList, err = netlink.RuleList(family)
		if err != nil {
			return nil, E.Cause(err, "list ", familyName, " rules")
		}
		tables := discoverAndroidVPNServiceTables(ruleList, r.tunOptions.Name)
		r.logger.Debug(familyName, " vpn service rules: vpn table ", vpnTable, ", default network tables ", strings.Join(common.Map(tables.physical, strconv.Itoa), " "), ", local network tables ", strings.Join(common.Map(tables.localNetworks, strconv.Itoa), " "))
		rules = append(rules, r.androidVPNServiceFamilyRules(family, vpnTable, tables)...)
	}
	return rules, nil
}

func androidVPNServiceRuleEquals(left *netlink.Rule, right *netlink.Rule) bool {
	return left.Family == right.Family &&
		left.Priority == right.Priority &&
		left.Mark == right.Mark &&
		left.Mask == right.Mask &&
		left.IifName == right.IifName &&
		left.Table == right.Table
}

func (r *autoRedirect) setupAndroidVPNServiceRules() error {
	r.androidVPNServiceRuleAccess.Lock()
	defer r.androidVPNServiceRuleAccess.Unlock()
	inputMark := r.tunOptions.AutoRedirectInputMark
	outputMark := r.tunOptions.AutoRedirectOutputMark
	resetMark := r.tunOptions.AutoRedirectResetMark
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, priority := range r.androidVPNServiceRulePriorities() {
			staleRules, err := netlink.RuleListFiltered(family, &netlink.Rule{Priority: priority}, netlink.RT_FILTER_PRIORITY)
			if err != nil {
				continue
			}
			for _, staleRule := range staleRules {
				if staleRule.Mark != inputMark && staleRule.Mark != outputMark && staleRule.Mark != resetMark {
					continue
				}
				deleteRule := netlink.NewRule()
				deleteRule.Family = family
				deleteRule.Priority = priority
				deleteRule.Mark = staleRule.Mark
				deleteRule.MarkSet = true
				deleteRule.Mask = staleRule.Mask
				_ = netlink.RuleDel(deleteRule)
			}
		}
	}
	rules, err := r.discoverAndroidVPNServiceRules()
	if err != nil {
		return err
	}
	r.androidVPNServiceRulesActive = true
	for _, rule := range rules {
		err = netlink.RuleAdd(rule)
		if err != nil && !E.IsMulti(err, unix.EEXIST, os.ErrExist) {
			return E.Cause(err, "add rule ", rule)
		}
		r.androidVPNServiceRules = append(r.androidVPNServiceRules, rule)
	}
	return r.removeAndroidIngressDiscardRulesLocked()
}

func (r *autoRedirect) updateAndroidVPNServiceRules() error {
	r.androidVPNServiceRuleAccess.Lock()
	defer r.androidVPNServiceRuleAccess.Unlock()
	if !r.androidVPNServiceRulesActive {
		return nil
	}
	rules, err := r.discoverAndroidVPNServiceRules()
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			return nil
		}
		return err
	}
	var currentRules []netlink.Rule
	for _, priority := range r.androidVPNServiceRulePriorities() {
		priorityRules, listErr := netlink.RuleListFiltered(netlink.FAMILY_ALL, &netlink.Rule{Priority: priority}, netlink.RT_FILTER_PRIORITY)
		if listErr != nil {
			return E.Cause(listErr, "list current vpn service rules")
		}
		currentRules = append(currentRules, priorityRules...)
	}
	var errorList []error
	var installedRules []*netlink.Rule
	for _, installedRule := range r.androidVPNServiceRules {
		if slices.ContainsFunc(rules, func(it *netlink.Rule) bool {
			return androidVPNServiceRuleEquals(it, installedRule)
		}) {
			continue
		}
		deleteErr := netlink.RuleDel(installedRule)
		if deleteErr != nil && !E.IsMulti(deleteErr, unix.ENOENT, os.ErrNotExist) {
			errorList = append(errorList, E.Cause(deleteErr, "delete rule ", installedRule))
			installedRules = append(installedRules, installedRule)
		}
	}
	for _, rule := range rules {
		if slices.ContainsFunc(currentRules, func(it netlink.Rule) bool {
			return androidVPNServiceRuleEquals(&it, rule)
		}) {
			installedRules = append(installedRules, rule)
			continue
		}
		addErr := netlink.RuleAdd(rule)
		if addErr != nil && !E.IsMulti(addErr, unix.EEXIST, os.ErrExist) {
			errorList = append(errorList, E.Cause(addErr, "add rule ", rule))
			continue
		}
		installedRules = append(installedRules, rule)
	}
	r.androidVPNServiceRules = installedRules
	errorList = append(errorList, r.removeAndroidIngressDiscardRulesLocked())
	return E.Errors(errorList...)
}

func (r *autoRedirect) cleanupAndroidVPNServiceRules() {
	r.androidVPNServiceRuleAccess.Lock()
	defer r.androidVPNServiceRuleAccess.Unlock()
	r.androidVPNServiceRulesActive = false
	r.restoreAndroidIngressDiscardRulesLocked()
	for _, rule := range r.androidVPNServiceRules {
		_ = netlink.RuleDel(rule)
	}
	r.androidVPNServiceRules = nil
}
