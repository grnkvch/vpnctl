package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

// PresetSelection preserves the boundary at which exclusion precedence is
// evaluated. Flattening exclusions across presets would make one preset able
// to suppress a destination explicitly included by another preset.
type PresetSelection struct {
	Name     string
	Includes []model.Selector
	Excludes []model.Selector
}

// PresetComposition is a canonical union of independently evaluated presets.
// Presets and both selector lists are sorted and independently owned.
type PresetComposition struct {
	Presets []PresetSelection
}

// NormalizePresetComposition validates complete preset ASTs, preserves their
// include-minus-exclude boundaries, and sorts away file-order differences. An
// explicit empty slice is a valid all-direct composition; nil is not.
func NormalizePresetComposition(presets []PresetAST) (PresetComposition, error) {
	if presets == nil {
		return PresetComposition{}, fmt.Errorf("preset composition input must be a present array")
	}
	composition := PresetComposition{Presets: make([]PresetSelection, len(presets))}
	for index, preset := range presets {
		if err := preset.Validate(); err != nil {
			return PresetComposition{}, fmt.Errorf("preset[%d]: %w", index, err)
		}
		selection := PresetSelection{
			Name: preset.Name, Includes: make([]model.Selector, 0, len(preset.Selectors)),
			Excludes: make([]model.Selector, 0, len(preset.Selectors)),
		}
		for _, selector := range preset.Selectors {
			if selector.Exclude {
				selection.Excludes = append(selection.Excludes, selector)
			} else {
				selection.Includes = append(selection.Includes, selector)
			}
		}
		composition.Presets[index] = selection
	}
	sort.Slice(composition.Presets, func(left, right int) bool {
		return strings.ToLower(composition.Presets[left].Name) < strings.ToLower(composition.Presets[right].Name)
	})
	if err := composition.Validate(); err != nil {
		return PresetComposition{}, err
	}
	return composition, nil
}

func (composition PresetComposition) Validate() error {
	if composition.Presets == nil {
		return fmt.Errorf("preset composition must contain a present presets array")
	}
	for index, preset := range composition.Presets {
		if err := validatePresetName(preset.Name); err != nil {
			return fmt.Errorf("presets[%d]: %w", index, err)
		}
		if index > 0 {
			previous := strings.ToLower(composition.Presets[index-1].Name)
			current := strings.ToLower(preset.Name)
			if previous == current {
				return fmt.Errorf("preset composition duplicates name %s", preset.Name)
			}
			if previous > current {
				return fmt.Errorf("preset composition names must be sorted")
			}
		}
		if preset.Includes == nil || preset.Excludes == nil {
			return fmt.Errorf("preset %s include and exclude arrays must be present", preset.Name)
		}
		if len(preset.Includes) == 0 {
			return fmt.Errorf("preset %s requires at least one include selector", preset.Name)
		}
		if len(preset.Includes)+len(preset.Excludes) > PresetMaximumSelectors {
			return fmt.Errorf("preset %s exceeds %d total selectors", preset.Name, PresetMaximumSelectors)
		}
		if err := validateCompositionSelectors(preset.Name, "include", preset.Includes, false); err != nil {
			return err
		}
		if err := validateCompositionSelectors(preset.Name, "exclude", preset.Excludes, true); err != nil {
			return err
		}
	}
	return nil
}

func validateCompositionSelectors(presetName, section string, selectors []model.Selector, exclude bool) error {
	for index, selector := range selectors {
		if selector.Exclude != exclude {
			return fmt.Errorf("preset %s %s[%d] has inconsistent exclusion state", presetName, section, index)
		}
		if err := selector.Validate(); err != nil {
			return fmt.Errorf("preset %s %s[%d]: %w", presetName, section, index, err)
		}
		if index > 0 && !presetSelectorLess(selectors[index-1], selector) {
			return fmt.Errorf("preset %s %s selectors must be strictly sorted and unique", presetName, section)
		}
	}
	return nil
}

// SelectsDomain evaluates every preset independently as include minus exclude,
// then unions those results. Exclusion therefore wins only inside its preset.
func (composition PresetComposition) SelectsDomain(domain string) (bool, error) {
	if err := composition.Validate(); err != nil {
		return false, err
	}
	if err := (model.Selector{Kind: model.SelectorDomain, Value: domain}).Validate(); err != nil {
		return false, fmt.Errorf("domain destination: %w", err)
	}
	return composition.selects(func(selector model.Selector) bool {
		switch selector.Kind {
		case model.SelectorDomain:
			return domain == selector.Value
		case model.SelectorDomainSuffix:
			return domain == selector.Value || strings.HasSuffix(domain, "."+selector.Value)
		default:
			return false
		}
	}), nil
}

// SelectsIP applies the same composition to a concrete IP destination. IPv4-
// mapped IPv6 input is normalized to its canonical IPv4 address first.
func (composition PresetComposition) SelectsIP(address netip.Addr) (bool, error) {
	if err := composition.Validate(); err != nil {
		return false, err
	}
	if !address.IsValid() || address.Zone() != "" {
		return false, fmt.Errorf("IP destination must be a valid unzoned address")
	}
	address = address.Unmap()
	return composition.selects(func(selector model.Selector) bool {
		if selector.Kind != model.SelectorIPCIDR {
			return false
		}
		prefix, err := netip.ParsePrefix(selector.Value)
		return err == nil && prefix.Contains(address)
	}), nil
}

func (composition PresetComposition) selects(matches func(model.Selector) bool) bool {
	for _, preset := range composition.Presets {
		included := false
		for _, selector := range preset.Includes {
			if matches(selector) {
				included = true
				break
			}
		}
		if !included {
			continue
		}
		excluded := false
		for _, selector := range preset.Excludes {
			if matches(selector) {
				excluded = true
				break
			}
		}
		if !excluded {
			return true
		}
	}
	return false
}
