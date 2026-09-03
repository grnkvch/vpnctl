package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

// MatcherIRSchemaVersion is independent from the public preset document
// schema. It versions the normalized, provider-neutral matching contract.
const MatcherIRSchemaVersion = 1

// MatcherIR is a canonical union of independently evaluated preset clauses.
// It intentionally contains no route action or outbound name: a successful
// match means gateway-or-block and a miss means direct at the product layer.
type MatcherIR struct {
	SchemaVersion int             `json:"schema_version"`
	Clauses       []MatcherClause `json:"clauses"`
}

type MatcherClause struct {
	Name     string       `json:"name"`
	Includes MatcherTerms `json:"includes"`
	Excludes MatcherTerms `json:"excludes"`
}

type MatcherTerms struct {
	Domains        []string `json:"domains"`
	DomainSuffixes []string `json:"domain_suffixes"`
	IPv4CIDRs      []string `json:"ipv4_cidrs"`
	IPv6CIDRs      []string `json:"ipv6_cidrs"`
}

// CompileMatcherIR converts the normalized preset composition into the only
// matching input accepted by data-plane target compilers.
func CompileMatcherIR(composition PresetComposition) (MatcherIR, error) {
	if err := composition.Validate(); err != nil {
		return MatcherIR{}, fmt.Errorf("validate matcher composition: %w", err)
	}
	ir := MatcherIR{SchemaVersion: MatcherIRSchemaVersion, Clauses: make([]MatcherClause, len(composition.Presets))}
	for index, preset := range composition.Presets {
		ir.Clauses[index] = MatcherClause{
			Name:     preset.Name,
			Includes: compileMatcherTerms(preset.Includes),
			Excludes: compileMatcherTerms(preset.Excludes),
		}
	}
	if err := ir.Validate(); err != nil {
		return MatcherIR{}, fmt.Errorf("validate compiled matcher IR: %w", err)
	}
	return ir, nil
}

func compileMatcherTerms(selectors []model.Selector) MatcherTerms {
	terms := MatcherTerms{
		Domains: []string{}, DomainSuffixes: []string{}, IPv4CIDRs: []string{}, IPv6CIDRs: []string{},
	}
	for _, selector := range selectors {
		switch selector.Kind {
		case model.SelectorDomain:
			terms.Domains = append(terms.Domains, selector.Value)
		case model.SelectorDomainSuffix:
			terms.DomainSuffixes = append(terms.DomainSuffixes, selector.Value)
		case model.SelectorIPCIDR:
			prefix := netip.MustParsePrefix(selector.Value)
			if prefix.Addr().Is4() {
				terms.IPv4CIDRs = append(terms.IPv4CIDRs, selector.Value)
			} else {
				terms.IPv6CIDRs = append(terms.IPv6CIDRs, selector.Value)
			}
		}
	}
	sort.Strings(terms.Domains)
	sort.Strings(terms.DomainSuffixes)
	sort.Strings(terms.IPv4CIDRs)
	sort.Strings(terms.IPv6CIDRs)
	return terms
}

func (ir MatcherIR) Validate() error {
	if ir.SchemaVersion != MatcherIRSchemaVersion {
		return fmt.Errorf("unsupported matcher IR schema_version %d", ir.SchemaVersion)
	}
	if ir.Clauses == nil {
		return fmt.Errorf("matcher IR clauses must be a present array")
	}
	for index, clause := range ir.Clauses {
		if err := validatePresetName(clause.Name); err != nil {
			return fmt.Errorf("clauses[%d]: %w", index, err)
		}
		if index > 0 {
			previous := strings.ToLower(ir.Clauses[index-1].Name)
			current := strings.ToLower(clause.Name)
			if previous >= current {
				return fmt.Errorf("matcher IR clause names must be strictly sorted and unique")
			}
		}
		includeCount, err := clause.Includes.validate(fmt.Sprintf("clauses[%d].includes", index))
		if err != nil {
			return err
		}
		excludeCount, err := clause.Excludes.validate(fmt.Sprintf("clauses[%d].excludes", index))
		if err != nil {
			return err
		}
		if includeCount == 0 {
			return fmt.Errorf("clauses[%d] requires at least one include matcher", index)
		}
		if includeCount+excludeCount > PresetMaximumSelectors {
			return fmt.Errorf("clauses[%d] exceeds %d total matchers", index, PresetMaximumSelectors)
		}
	}
	return nil
}

func (terms MatcherTerms) validate(path string) (int, error) {
	if terms.Domains == nil || terms.DomainSuffixes == nil || terms.IPv4CIDRs == nil || terms.IPv6CIDRs == nil {
		return 0, fmt.Errorf("%s matcher arrays must be present", path)
	}
	if err := validateSortedMatcherDomains(path+".domains", model.SelectorDomain, terms.Domains); err != nil {
		return 0, err
	}
	if err := validateSortedMatcherDomains(path+".domain_suffixes", model.SelectorDomainSuffix, terms.DomainSuffixes); err != nil {
		return 0, err
	}
	if err := validateSortedMatcherCIDRs(path+".ipv4_cidrs", terms.IPv4CIDRs, true); err != nil {
		return 0, err
	}
	if err := validateSortedMatcherCIDRs(path+".ipv6_cidrs", terms.IPv6CIDRs, false); err != nil {
		return 0, err
	}
	return len(terms.Domains) + len(terms.DomainSuffixes) + len(terms.IPv4CIDRs) + len(terms.IPv6CIDRs), nil
}

func validateSortedMatcherDomains(path string, kind model.SelectorKind, values []string) error {
	for index, value := range values {
		if err := (model.Selector{Kind: kind, Value: value}).Validate(); err != nil {
			return fmt.Errorf("%s[%d]: %w", path, index, err)
		}
		if index > 0 && values[index-1] >= value {
			return fmt.Errorf("%s must be strictly sorted and unique", path)
		}
	}
	return nil
}

func validateSortedMatcherCIDRs(path string, values []string, ipv4 bool) error {
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || prefix.Masked() != prefix || prefix.Addr().Is4() != ipv4 {
			family := "IPv6"
			if ipv4 {
				family = "IPv4"
			}
			return fmt.Errorf("%s[%d] must be a canonical %s prefix", path, index, family)
		}
		if index > 0 && values[index-1] >= value {
			return fmt.Errorf("%s must be strictly sorted and unique", path)
		}
	}
	return nil
}

func (ir MatcherIR) SelectsDomain(domain string) (bool, error) {
	if err := ir.Validate(); err != nil {
		return false, err
	}
	if err := (model.Selector{Kind: model.SelectorDomain, Value: domain}).Validate(); err != nil {
		return false, fmt.Errorf("domain destination: %w", err)
	}
	return ir.selectsDomain(domain), nil
}

func (ir MatcherIR) selectsDomain(domain string) bool {
	for _, clause := range ir.Clauses {
		if clause.Includes.matchesDomain(domain) && !clause.Excludes.matchesDomain(domain) {
			return true
		}
	}
	return false
}

func (ir MatcherIR) SelectsIP(address netip.Addr) (bool, error) {
	if err := ir.Validate(); err != nil {
		return false, err
	}
	if !address.IsValid() || address.Zone() != "" {
		return false, fmt.Errorf("IP destination must be a valid unzoned address")
	}
	address = address.Unmap()
	return ir.selectsIP(address), nil
}

func (ir MatcherIR) selectsIP(address netip.Addr) bool {
	for _, clause := range ir.Clauses {
		if clause.Includes.matchesIP(address) && !clause.Excludes.matchesIP(address) {
			return true
		}
	}
	return false
}

func (terms MatcherTerms) matchesDomain(domain string) bool {
	for _, exact := range terms.Domains {
		if domain == exact {
			return true
		}
	}
	for _, suffix := range terms.DomainSuffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func (terms MatcherTerms) matchesIP(address netip.Addr) bool {
	values := terms.IPv6CIDRs
	if address.Is4() {
		values = terms.IPv4CIDRs
	}
	for _, value := range values {
		if netip.MustParsePrefix(value).Contains(address) {
			return true
		}
	}
	return false
}

// MatcherDecisionRule is target output, not part of MatcherIR. Selected=true
// maps to the target's gateway-or-block route; false is an ordered exception
// that retains the direct classification.
type MatcherDecisionRule struct {
	Kind     model.SelectorKind
	Value    string
	Selected bool
}

type matcherDecisionProgram struct {
	schemaVersion int
	domain        []MatcherDecisionRule
	ipv4          []MatcherDecisionRule
	ipv6          []MatcherDecisionRule
}

// NodeRoutingMatchers feeds the node Mihomo rule renderer in task 10.2.
type NodeRoutingMatchers struct{ program matcherDecisionProgram }

// NFTablesLeakGuardMatchers feeds static address rules and resolver-populated
// protected address sets. nftables cannot inspect a DNS name in an IP packet,
// so resolvedDomain is evaluated when the managed resolver observes answers.
type NFTablesLeakGuardMatchers struct{ program matcherDecisionProgram }

// GatewayDNSMatchers selects queries which must use the gateway DNS path.
// IP/CIDR matchers classify connections and intentionally do not select a DNS
// query before its answer exists.
type GatewayDNSMatchers struct {
	schemaVersion int
	domain        []MatcherDecisionRule
}

// ClashMatchers feeds both rules and nameserver-policy in client exports.
type ClashMatchers struct{ program matcherDecisionProgram }

func CompileNodeRoutingMatchers(ir MatcherIR) (NodeRoutingMatchers, error) {
	program, err := compileMatcherDecisionProgram(ir)
	if err != nil {
		return NodeRoutingMatchers{}, err
	}
	return NodeRoutingMatchers{program: program}, nil
}

func CompileNFTablesLeakGuardMatchers(ir MatcherIR) (NFTablesLeakGuardMatchers, error) {
	program, err := compileMatcherDecisionProgram(ir)
	if err != nil {
		return NFTablesLeakGuardMatchers{}, err
	}
	return NFTablesLeakGuardMatchers{program: program}, nil
}

func CompileGatewayDNSMatchers(ir MatcherIR) (GatewayDNSMatchers, error) {
	program, err := compileMatcherDecisionProgram(ir)
	if err != nil {
		return GatewayDNSMatchers{}, err
	}
	return GatewayDNSMatchers{
		schemaVersion: MatcherIRSchemaVersion,
		domain:        append([]MatcherDecisionRule(nil), program.domain...),
	}, nil
}

func CompileClashMatchers(ir MatcherIR) (ClashMatchers, error) {
	program, err := compileMatcherDecisionProgram(ir)
	if err != nil {
		return ClashMatchers{}, err
	}
	return ClashMatchers{program: program}, nil
}

func compileMatcherDecisionProgram(ir MatcherIR) (matcherDecisionProgram, error) {
	if err := ir.Validate(); err != nil {
		return matcherDecisionProgram{}, fmt.Errorf("validate matcher IR: %w", err)
	}
	domain, err := compileDomainDecisionRules(ir)
	if err != nil {
		return matcherDecisionProgram{}, err
	}
	ipv4, ipv6, err := compileIPDecisionRules(ir)
	if err != nil {
		return matcherDecisionProgram{}, err
	}
	return matcherDecisionProgram{schemaVersion: MatcherIRSchemaVersion, domain: domain, ipv4: ipv4, ipv6: ipv6}, nil
}

func compileDomainDecisionRules(ir MatcherIR) ([]MatcherDecisionRule, error) {
	exact := make(map[string]struct{})
	suffixes := make(map[string]struct{})
	for _, clause := range ir.Clauses {
		for _, terms := range []MatcherTerms{clause.Includes, clause.Excludes} {
			for _, value := range terms.Domains {
				exact[value] = struct{}{}
			}
			for _, value := range terms.DomainSuffixes {
				suffixes[value] = struct{}{}
			}
		}
	}
	exactValues := sortedMatcherKeys(exact)
	suffixValues := sortedMatcherKeys(suffixes)
	sort.Slice(suffixValues, func(left, right int) bool {
		leftLabels := strings.Count(suffixValues[left], ".")
		rightLabels := strings.Count(suffixValues[right], ".")
		if leftLabels != rightLabels {
			return leftLabels > rightLabels
		}
		if len(suffixValues[left]) != len(suffixValues[right]) {
			return len(suffixValues[left]) > len(suffixValues[right])
		}
		return suffixValues[left] < suffixValues[right]
	})

	rules := make([]MatcherDecisionRule, 0, len(exactValues)+len(suffixValues))
	for _, value := range exactValues {
		rules = append(rules, MatcherDecisionRule{Kind: model.SelectorDomain, Value: value, Selected: ir.selectsDomain(value)})
	}
	for _, value := range suffixValues {
		probe, found := uncoveredDomainForMatcherSuffix(value, exact, suffixes)
		if !found {
			continue
		}
		rules = append(rules, MatcherDecisionRule{Kind: model.SelectorDomainSuffix, Value: value, Selected: ir.selectsDomain(probe)})
	}
	return rules, nil
}

func compileIPDecisionRules(ir MatcherIR) ([]MatcherDecisionRule, []MatcherDecisionRule, error) {
	sets := [2]map[string]netip.Prefix{{}, {}}
	for _, clause := range ir.Clauses {
		for _, terms := range []MatcherTerms{clause.Includes, clause.Excludes} {
			for _, value := range terms.IPv4CIDRs {
				sets[0][value] = netip.MustParsePrefix(value)
			}
			for _, value := range terms.IPv6CIDRs {
				sets[1][value] = netip.MustParsePrefix(value)
			}
		}
	}
	programs := [2][]MatcherDecisionRule{}
	for family, set := range sets {
		prefixes := make([]netip.Prefix, 0, len(set))
		for _, prefix := range set {
			prefixes = append(prefixes, prefix)
		}
		sort.Slice(prefixes, func(left, right int) bool {
			if prefixes[left].Bits() != prefixes[right].Bits() {
				return prefixes[left].Bits() > prefixes[right].Bits()
			}
			return prefixes[left].Addr().Compare(prefixes[right].Addr()) < 0
		})
		for _, prefix := range prefixes {
			covered := make([]netip.Prefix, 0)
			for _, candidate := range prefixes {
				if candidate.Bits() > prefix.Bits() && prefix.Contains(candidate.Addr()) {
					covered = append(covered, candidate)
				}
			}
			probe, found := uncoveredMatcherAddress(prefix, covered)
			if !found {
				continue
			}
			programs[family] = append(programs[family], MatcherDecisionRule{
				Kind: model.SelectorIPCIDR, Value: prefix.String(), Selected: ir.selectsIP(probe),
			})
		}
	}
	return programs[0], programs[1], nil
}

func sortedMatcherKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uncoveredDomainForMatcherSuffix(suffix string, exact, suffixes map[string]struct{}) (string, bool) {
	if _, covered := exact[suffix]; !covered {
		return suffix, true
	}
	labels := make([]string, 0, len(exact)+len(suffixes)+36)
	for character := 'a'; character <= 'z'; character++ {
		labels = append(labels, string(character))
	}
	for character := '0'; character <= '9'; character++ {
		labels = append(labels, string(character))
	}
	for index := 0; index <= len(exact)+len(suffixes); index++ {
		labels = append(labels, "v"+strconv.Itoa(index))
	}
	for _, label := range labels {
		candidate := label + "." + suffix
		if err := (model.Selector{Kind: model.SelectorDomain, Value: candidate}).Validate(); err != nil {
			continue
		}
		if _, covered := exact[candidate]; covered {
			continue
		}
		covered := false
		for descendant := range suffixes {
			if descendant != suffix && (candidate == descendant || strings.HasSuffix(candidate, "."+descendant)) {
				covered = true
				break
			}
		}
		if !covered {
			return candidate, true
		}
	}
	return "", false
}

func uncoveredMatcherAddress(prefix netip.Prefix, covered []netip.Prefix) (netip.Addr, bool) {
	if len(covered) == 0 {
		return prefix.Addr(), true
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		return netip.Addr{}, false
	}
	left, right := splitMatcherPrefix(prefix)
	for _, half := range []netip.Prefix{left, right} {
		descendants := make([]netip.Prefix, 0, len(covered))
		fullyCovered := false
		for _, candidate := range covered {
			if candidate == half {
				fullyCovered = true
				break
			}
			if candidate.Bits() > half.Bits() && half.Contains(candidate.Addr()) {
				descendants = append(descendants, candidate)
			}
		}
		if fullyCovered {
			continue
		}
		if address, found := uncoveredMatcherAddress(half, descendants); found {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func splitMatcherPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits() + 1
	address := prefix.Addr()
	if address.Is4() {
		raw := address.As4()
		raw[(bits-1)/8] |= byte(1 << (7 - ((bits - 1) % 8)))
		return netip.PrefixFrom(address, bits).Masked(), netip.PrefixFrom(netip.AddrFrom4(raw), bits).Masked()
	}
	raw := address.As16()
	raw[(bits-1)/8] |= byte(1 << (7 - ((bits - 1) % 8)))
	return netip.PrefixFrom(address, bits).Masked(), netip.PrefixFrom(netip.AddrFrom16(raw), bits).Masked()
}

func (matcher NodeRoutingMatchers) SelectsDomain(domain string) (bool, error) {
	return matcher.program.selectsDomain(domain)
}

func (matcher NodeRoutingMatchers) SelectsIP(address netip.Addr) (bool, error) {
	return matcher.program.selectsIP(address)
}

func (matcher NFTablesLeakGuardMatchers) SelectsResolvedDomain(domain string) (bool, error) {
	return matcher.program.selectsDomain(domain)
}

func (matcher NFTablesLeakGuardMatchers) SelectsIP(address netip.Addr) (bool, error) {
	return matcher.program.selectsIP(address)
}

func (matcher GatewayDNSMatchers) SelectsDomain(domain string) (bool, error) {
	if matcher.schemaVersion != MatcherIRSchemaVersion {
		return false, fmt.Errorf("gateway DNS matchers are not compiled")
	}
	return selectDomainDecision(matcher.domain, domain)
}

func (matcher ClashMatchers) SelectsDomain(domain string) (bool, error) {
	return matcher.program.selectsDomain(domain)
}

func (matcher ClashMatchers) SelectsIP(address netip.Addr) (bool, error) {
	return matcher.program.selectsIP(address)
}

func (program matcherDecisionProgram) selectsDomain(domain string) (bool, error) {
	if program.schemaVersion != MatcherIRSchemaVersion {
		return false, fmt.Errorf("matcher target is not compiled")
	}
	return selectDomainDecision(program.domain, domain)
}

func selectDomainDecision(rules []MatcherDecisionRule, domain string) (bool, error) {
	if err := (model.Selector{Kind: model.SelectorDomain, Value: domain}).Validate(); err != nil {
		return false, fmt.Errorf("domain destination: %w", err)
	}
	for _, rule := range rules {
		switch rule.Kind {
		case model.SelectorDomain:
			if domain == rule.Value {
				return rule.Selected, nil
			}
		case model.SelectorDomainSuffix:
			if domain == rule.Value || strings.HasSuffix(domain, "."+rule.Value) {
				return rule.Selected, nil
			}
		}
	}
	return false, nil
}

func (program matcherDecisionProgram) selectsIP(address netip.Addr) (bool, error) {
	if program.schemaVersion != MatcherIRSchemaVersion {
		return false, fmt.Errorf("matcher target is not compiled")
	}
	if !address.IsValid() || address.Zone() != "" {
		return false, fmt.Errorf("IP destination must be a valid unzoned address")
	}
	address = address.Unmap()
	rules := program.ipv6
	if address.Is4() {
		rules = program.ipv4
	}
	for _, rule := range rules {
		if netip.MustParsePrefix(rule.Value).Contains(address) {
			return rule.Selected, nil
		}
	}
	return false, nil
}

func (matcher ClashMatchers) clashRules() []clashRule {
	rules := make([]clashRule, 0, len(matcher.program.domain)+len(matcher.program.ipv4)+len(matcher.program.ipv6))
	for _, rule := range matcher.program.domain {
		rules = append(rules, clashRule{Kind: rule.Kind, Value: rule.Value, Selected: rule.Selected})
	}
	for _, rule := range matcher.program.ipv4 {
		rules = append(rules, clashRule{Kind: rule.Kind, Value: rule.Value, Selected: rule.Selected})
	}
	for _, rule := range matcher.program.ipv6 {
		rules = append(rules, clashRule{Kind: rule.Kind, Value: rule.Value, Selected: rule.Selected})
	}
	return rules
}
