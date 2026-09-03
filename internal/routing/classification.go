package routing

import (
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const ClassificationBoundarySchemaVersion = 1

// ClassificationBoundary states where vpnctl's fail-closed promise begins.
// It is diagnostic metadata only: it never expands selectors and never emits
// a provider list or a global DoH/DoT firewall action.
type ClassificationBoundary struct {
	SchemaVersion       int
	DomainSelectors     int
	AddressSelectors    int
	SelectedAction      string
	UnmatchedAction     string
	ClassicDNS          string
	DoH                 string
	DoT                 string
	HardcodedIP         string
	GlobalDoHDotBlocked bool
}

func InspectClassificationBoundary(selectors []model.Selector) (ClassificationBoundary, error) {
	if selectors == nil {
		return ClassificationBoundary{}, fmt.Errorf("classification selectors must be a present array")
	}
	report := ClassificationBoundary{
		SchemaVersion:  ClassificationBoundarySchemaVersion,
		SelectedAction: "gateway_or_block", UnmatchedAction: "direct", ClassicDNS: "managed",
		DoH: "domain_hidden_unless_address_selected", DoT: "domain_hidden_unless_address_selected",
		HardcodedIP: "address_selector_required", GlobalDoHDotBlocked: false,
	}
	for index, selector := range selectors {
		if err := selector.Validate(); err != nil {
			return ClassificationBoundary{}, fmt.Errorf("classification selector %d: %w", index, err)
		}
		switch selector.Kind {
		case model.SelectorDomain, model.SelectorDomainSuffix:
			report.DomainSelectors++
		case model.SelectorIPCIDR:
			report.AddressSelectors++
		}
	}
	return report, nil
}

func (report ClassificationBoundary) Validate() error {
	if report.SchemaVersion != ClassificationBoundarySchemaVersion || report.DomainSelectors < 0 || report.AddressSelectors < 0 ||
		report.SelectedAction != "gateway_or_block" || report.UnmatchedAction != "direct" || report.ClassicDNS != "managed" ||
		report.DoH != "domain_hidden_unless_address_selected" || report.DoT != "domain_hidden_unless_address_selected" ||
		report.HardcodedIP != "address_selector_required" || report.GlobalDoHDotBlocked {
		return fmt.Errorf("invalid classification boundary report")
	}
	return nil
}

func (report ClassificationBoundary) SafeObject() output.SafeObject {
	return output.SafeObject{
		"schema_version":   report.SchemaVersion,
		"domain_selectors": report.DomainSelectors, "address_selectors": report.AddressSelectors,
		"selected_action": report.SelectedAction, "unmatched_action": report.UnmatchedAction,
		"classic_dns": report.ClassicDNS, "doh": report.DoH, "dot": report.DoT,
		"hardcoded_ip": report.HardcodedIP, "global_doh_dot_blocked": report.GlobalDoHDotBlocked,
	}
}

func (report ClassificationBoundary) Warnings() []output.Message {
	return []output.Message{
		{
			Code:    "classification_boundary",
			Message: "Domain selectors cannot identify independent DoH or DoT requests or hardcoded IP destinations; unmatched traffic remains direct unless an IP or CIDR selector matches it.",
		},
	}
}
