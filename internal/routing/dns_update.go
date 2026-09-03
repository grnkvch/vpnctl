package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"go.yaml.in/yaml/v3"
)

const dnsConfigFileMode = 0o600

// ReplaceDNSUpstreams builds the only state transition accepted by the DNS
// commands. The role fixes the scope, so a command can never update both the
// gateway and direct paths or introduce an implicit fallback between them.
func ReplaceDNSUpstreams(state model.State, upstreams []string) (model.State, bool, error) {
	if err := state.Validate(); err != nil {
		return model.State{}, false, fmt.Errorf("validate DNS state: %w", err)
	}
	if state.DNS == nil {
		return model.State{}, false, fmt.Errorf("host has no role-owned DNS state")
	}
	candidateDNS := model.DNSUpstreamState{
		SchemaVersion: model.ResourceSchemaVersion,
		Scope:         state.DNS.Scope,
		IPv4:          append([]string(nil), upstreams...),
	}
	if err := candidateDNS.Validate(); err != nil {
		return model.State{}, false, err
	}
	if reflect.DeepEqual(state.DNS.IPv4, candidateDNS.IPv4) {
		return state, false, nil
	}
	next, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, false, err
	}
	candidate := state
	candidate.Generation = next
	candidate.DNS = &candidateDNS
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, false, err
	}
	return candidate, true, nil
}

// RewriteNodeRoutingDNS changes only the direct resolver references in an
// already validated generated Mihomo document. It intentionally preserves the
// current policy/direct mode and every matcher, transport, and secret field.
func RewriteNodeRoutingDNS(content []byte, expected, replacement []string) ([]byte, RoutingDNSMode, error) {
	mode, err := nodeRoutingConfigDNSMode(content)
	if err != nil {
		return nil, "", err
	}
	if err := ValidateNodeRoutingConfig(content, mode); err != nil {
		return nil, "", fmt.Errorf("validate current node routing config: %w", err)
	}
	oldDNS, err := normalizeNodeDirectDNS(expected)
	if err != nil {
		return nil, "", fmt.Errorf("validate expected node direct DNS: %w", err)
	}
	newDNS, err := normalizeNodeDirectDNS(replacement)
	if err != nil {
		return nil, "", fmt.Errorf("validate replacement node direct DNS: %w", err)
	}
	var document nodeRoutingDocument
	if err := decodeNodeRoutingYAML(content, &document); err != nil {
		return nil, "", err
	}
	current, err := validateNodeRoutingDNS(document.DNS, mode)
	if err != nil {
		return nil, "", err
	}
	if !reflect.DeepEqual(current, oldDNS) {
		return nil, "", fmt.Errorf("node routing DNS config drifted from authoritative state")
	}

	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil || len(root.Content) != 1 {
		return nil, "", fmt.Errorf("decode node routing YAML tree")
	}
	dnsNode, ok := yamlMappingValue(root.Content[0], "dns")
	if !ok || dnsNode.Kind != yaml.MappingNode {
		return nil, "", fmt.Errorf("node routing YAML lacks DNS mapping")
	}
	defaults, ok := yamlMappingValue(dnsNode, "default-nameserver")
	if !ok || defaults.Kind != yaml.SequenceNode {
		return nil, "", fmt.Errorf("node routing YAML lacks default nameservers")
	}
	setYAMLSequence(defaults, newDNS)
	nameservers, ok := yamlMappingValue(dnsNode, "nameserver")
	if !ok || nameservers.Kind != yaml.SequenceNode {
		return nil, "", fmt.Errorf("node routing YAML lacks nameservers")
	}
	setYAMLSequence(nameservers, directDNSURIs(newDNS))
	if policies, present := yamlMappingValue(dnsNode, "nameserver-policy"); present {
		if policies.Kind != yaml.MappingNode {
			return nil, "", fmt.Errorf("node routing YAML has invalid nameserver policy")
		}
		for index := 1; index < len(policies.Content); index += 2 {
			values := policies.Content[index]
			if values.Kind != yaml.SequenceNode || len(values.Content) == 0 {
				return nil, "", fmt.Errorf("node routing YAML has invalid nameserver policy target")
			}
			direct := true
			for _, value := range values.Content {
				if value.Value == "" || !bytes.HasSuffix([]byte(value.Value), []byte("#"+NodeRoutingDirectDNSProxy)) {
					direct = false
					break
				}
			}
			if direct {
				setYAMLSequence(values, directDNSURIs(newDNS))
			}
		}
	}

	var encoded bytes.Buffer
	encoder := yaml.NewEncoder(&encoded)
	encoder.SetIndent(2)
	if err := encoder.Encode(root.Content[0]); err != nil {
		return nil, "", fmt.Errorf("encode updated node routing config: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, "", fmt.Errorf("finish updated node routing config: %w", err)
	}
	updated := encoded.Bytes()
	if err := ValidateNodeRoutingConfig(updated, mode); err != nil {
		return nil, "", fmt.Errorf("validate updated node routing config: %w", err)
	}
	return append([]byte(nil), updated...), mode, nil
}

func directDNSURIs(servers []string) []string {
	result := make([]string, len(servers))
	for index, server := range servers {
		result[index] = nodeDirectDNSURI(server)
	}
	return result
}

func yamlMappingValue(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1], true
		}
	}
	return nil, false
}

func setYAMLSequence(sequence *yaml.Node, values []string) {
	sequence.Kind = yaml.SequenceNode
	sequence.Tag = "!!seq"
	sequence.Content = make([]*yaml.Node, len(values))
	for index, value := range values {
		sequence.Content[index] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	}
}

// DNSConfigTransaction stages one exact generated-file replacement. Apply and
// rollback both restart only the owning data-plane unit, which clears Mihomo's
// DNS cache on node changes and never touches node/client artifacts for a
// gateway-only upstream change.
type DNSConfigTransaction struct {
	path    string
	unit    string
	before  []byte
	after   []byte
	runner  linuxplatform.ProbeRunner
	runtime bool
	applied bool
}

func PrepareGatewayDNSConfigTransaction(paths store.Paths, runner linuxplatform.ProbeRunner, before, after model.State) (*DNSConfigTransaction, error) {
	if runner == nil {
		return nil, fmt.Errorf("gateway DNS update runner is required")
	}
	oldCandidate, err := RenderGatewayDNSConfig(before)
	if err != nil {
		return nil, err
	}
	newCandidate, err := RenderGatewayDNSConfig(after)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(paths.ConfigDir, "generated", "gateway", GatewayDNSConfigFileName)
	if err := verifyManagedDNSConfig(path, oldCandidate.Bytes()); err != nil {
		return nil, err
	}
	return &DNSConfigTransaction{path: path, unit: "vpnctl-dns.service", before: oldCandidate.Bytes(), after: newCandidate.Bytes(), runner: runner, runtime: true}, nil
}

func PrepareNodeDNSConfigTransaction(paths store.Paths, runner linuxplatform.ProbeRunner, before, after model.State) (*DNSConfigTransaction, error) {
	if runner == nil {
		return nil, fmt.Errorf("node DNS update runner is required")
	}
	if before.Host.Role != model.RoleNode || after.Host.Role != model.RoleNode || before.DNS == nil || after.DNS == nil {
		return nil, fmt.Errorf("node DNS update requires node-owned state")
	}
	if len(before.Nodes) == 0 {
		return &DNSConfigTransaction{runner: runner}, nil
	}
	path := nodeRoutingConfigPath(paths)
	content, err := readManagedDNSConfig(path)
	if err != nil {
		return nil, err
	}
	updated, _, err := RewriteNodeRoutingDNS(content, before.DNS.IPv4, after.DNS.IPv4)
	if err != nil {
		return nil, err
	}
	return &DNSConfigTransaction{path: path, unit: "vpnctl-routing.service", before: content, after: updated, runner: runner, runtime: true}, nil
}

func (transaction *DNSConfigTransaction) Apply(ctx context.Context) error {
	if transaction == nil || transaction.runner == nil {
		return fmt.Errorf("DNS config transaction is incomplete")
	}
	if !transaction.runtime || bytes.Equal(transaction.before, transaction.after) {
		return nil
	}
	if err := verifyManagedDNSConfig(transaction.path, transaction.before); err != nil {
		return fmt.Errorf("refuse DNS activation after config drift: %w", err)
	}
	if err := replaceManagedDNSConfig(transaction.path, transaction.after); err != nil {
		return err
	}
	transaction.applied = true
	if err := transaction.restart(ctx); err != nil {
		rollbackContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rollbackErr := transaction.Rollback(rollbackContext)
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback DNS config: %w", rollbackErr))
		}
		return err
	}
	return nil
}

func (transaction *DNSConfigTransaction) Rollback(ctx context.Context) error {
	if transaction == nil || !transaction.applied || !transaction.runtime {
		return nil
	}
	if err := verifyManagedDNSConfig(transaction.path, transaction.after); err != nil {
		return fmt.Errorf("refuse DNS rollback after config drift: %w", err)
	}
	if err := replaceManagedDNSConfig(transaction.path, transaction.before); err != nil {
		return err
	}
	transaction.applied = false
	return transaction.restart(ctx)
}

func (transaction *DNSConfigTransaction) restart(ctx context.Context) error {
	result, err := transaction.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", transaction.unit}})
	if err != nil {
		return fmt.Errorf("restart %s: %w", transaction.unit, err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("restart %s failed", transaction.unit)
	}
	return nil
}

func verifyManagedDNSConfig(path string, expected []byte) error {
	content, err := readManagedDNSConfig(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, expected) {
		return fmt.Errorf("managed DNS config drifted from authoritative state")
	}
	return nil
}

func readManagedDNSConfig(path string) ([]byte, error) {
	content, err := readNodeDNSBoundedFile(path, maximumNodeRoutingConfigBytes, dnsConfigFileMode)
	if err != nil {
		return nil, fmt.Errorf("read root-only managed DNS config: %w", err)
	}
	return content, nil
}

func replaceManagedDNSConfig(path string, content []byte) error {
	if err := verifyManagedDNSParent(filepath.Dir(path)); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vpnctl-dns-*.tmp")
	if err != nil {
		return fmt.Errorf("stage managed DNS config: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(dnsConfigFileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate managed DNS config: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func verifyManagedDNSParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("managed DNS config parent must be a root-only real directory")
	}
	return nil
}
