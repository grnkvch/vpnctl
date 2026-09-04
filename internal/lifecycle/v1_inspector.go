package lifecycle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"

	v1state "github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	V1InspectionSchemaVersion = 1
	v1StateDirectoryName      = ".vpnctl"
	v1MaximumStateBytes       = 4 << 20
	v1MaximumRulesetBytes     = 1 << 20
	v1MaximumGeneratedBytes   = 8 << 20
	v1MaximumGeneratedTotal   = 64 << 20
	v1MaximumGeneratedFiles   = 4096
	v1MaximumSystemFileBytes  = 4 << 20
	v1MaximumSecretBytes      = 1024
)

type V1InspectionStatus string

const (
	V1InspectionAbsent      V1InspectionStatus = "absent"
	V1InspectionReady       V1InspectionStatus = "ready"
	V1InspectionPartial     V1InspectionStatus = "partial"
	V1InspectionInvalid     V1InspectionStatus = "invalid"
	V1InspectionUnsupported V1InspectionStatus = "unsupported"
)

type V1IssueSeverity string

const (
	V1IssueInfo    V1IssueSeverity = "info"
	V1IssueWarning V1IssueSeverity = "warning"
	V1IssueError   V1IssueSeverity = "error"
)

type V1InspectionIssue struct {
	Severity V1IssueSeverity `json:"severity"`
	Code     string          `json:"code"`
	Scope    string          `json:"scope"`
	Path     string          `json:"path,omitempty"`
	Message  string          `json:"message"`
}

type V1ServerSummary struct {
	Present            bool     `json:"present"`
	ID                 string   `json:"id,omitempty"`
	Name               string   `json:"name,omitempty"`
	PublicEndpoint     string   `json:"public_endpoint,omitempty"`
	WireGuardInterface string   `json:"wireguard_interface,omitempty"`
	WireGuardPort      int      `json:"wireguard_port,omitempty"`
	WireGuardSubnet    string   `json:"wireguard_subnet,omitempty"`
	WireGuardPublicKey string   `json:"wireguard_public_key,omitempty"`
	DNSServers         []string `json:"dns_servers"`
	ExternalInterface  string   `json:"external_interface,omitempty"`
	PrivateKeyPresent  bool     `json:"private_key_present"`
	PrivateKeyValid    bool     `json:"private_key_valid"`
	KeyPairMatches     bool     `json:"key_pair_matches"`
}

type V1ClientSummary struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Platform           string    `json:"platform"`
	Status             string    `json:"status"`
	AssignedIP         string    `json:"assigned_ip"`
	WireGuardPublicKey string    `json:"wireguard_public_key"`
	Tags               []string  `json:"tags"`
	CreatedAt          time.Time `json:"created_at"`
	PrivateKeyPresent  bool      `json:"private_key_present"`
	PrivateKeyValid    bool      `json:"private_key_valid"`
	KeyPairMatches     bool      `json:"key_pair_matches"`
}

type V1RulesetSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	DomainCount int    `json:"domain_count"`
}

type V1GeneratedArtifact struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	ClientID string `json:"client_id,omitempty"`
	Bytes    int64  `json:"bytes"`
	Mode     uint32 `json:"mode"`
}

type V1SystemArtifact struct {
	Path         string `json:"path"`
	Present      bool   `json:"present"`
	Regular      bool   `json:"regular"`
	Mode         uint32 `json:"mode,omitempty"`
	Bytes        int64  `json:"bytes,omitempty"`
	MatchesState bool   `json:"matches_state"`
}

type V1UFWRule struct {
	Family         string `json:"family"`
	Action         string `json:"action"`
	Protocol       string `json:"protocol"`
	Port           int    `json:"port"`
	Direction      string `json:"direction"`
	Classification string `json:"classification"`
}

type V1UFWReport struct {
	ConfigPresent bool        `json:"config_present"`
	Enabled       *bool       `json:"enabled,omitempty"`
	Rules         []V1UFWRule `json:"rules"`
}

type V1InspectionReport struct {
	SchemaVersion      int                   `json:"schema_version"`
	Status             V1InspectionStatus    `json:"status"`
	StateDirectory     string                `json:"state_directory"`
	StatePresent       bool                  `json:"state_present"`
	StateSchemaVersion int                   `json:"state_schema_version,omitempty"`
	Server             V1ServerSummary       `json:"server"`
	Clients            []V1ClientSummary     `json:"clients"`
	Rulesets           []V1RulesetSummary    `json:"rulesets"`
	Generated          []V1GeneratedArtifact `json:"generated"`
	WireGuardConfig    V1SystemArtifact      `json:"wireguard_config"`
	ForwardingConfig   V1SystemArtifact      `json:"forwarding_config"`
	UFW                V1UFWReport           `json:"ufw"`
	Issues             []V1InspectionIssue   `json:"issues"`
}

// V1Inspection keeps migration inputs private while exposing only the
// redacted report. Generated profiles and WireGuard config may contain private
// keys, so callers must destroy the snapshot after use.
type V1Inspection struct {
	Report V1InspectionReport

	state           v1state.State
	rulesets        map[string]v1state.Ruleset
	privateKeys     map[string][]byte
	generated       map[string][]byte
	systemWireGuard []byte
	destroyed       bool
}

func (inspection V1Inspection) String() string {
	data, err := json.Marshal(inspection.Report)
	if err != nil {
		return "<v1-inspection>"
	}
	return string(data)
}

func (inspection V1Inspection) GoString() string { return inspection.String() }
func (inspection V1Inspection) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, inspection.String())
}
func (inspection V1Inspection) MarshalJSON() ([]byte, error) {
	return json.Marshal(inspection.Report)
}

func (inspection *V1Inspection) Destroy() {
	if inspection == nil || inspection.destroyed {
		return
	}
	for _, key := range inspection.privateKeys {
		clear(key)
	}
	for _, artifact := range inspection.generated {
		clear(artifact)
	}
	clear(inspection.systemWireGuard)
	inspection.privateKeys = nil
	inspection.generated = nil
	inspection.systemWireGuard = nil
	inspection.rulesets = nil
	inspection.state = v1state.State{}
	inspection.destroyed = true
}

type V1InstallationInspector struct {
	workspaceRoot string
	stateRoot     string
	systemRoot    string
}

func NewV1InstallationInspector(workspaceRoot, systemRoot string) (*V1InstallationInspector, error) {
	if workspaceRoot == "" {
		current, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("resolve current workspace: %w", err)
		}
		workspaceRoot = current
	}
	workspaceRoot, err := canonicalV1Root(workspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve v1 workspace: %w", err)
	}
	if systemRoot == "" {
		systemRoot = string(filepath.Separator)
	}
	systemRoot, err = canonicalV1Root(systemRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve v1 system root: %w", err)
	}
	return &V1InstallationInspector{
		workspaceRoot: workspaceRoot,
		stateRoot:     filepath.Join(workspaceRoot, v1StateDirectoryName),
		systemRoot:    systemRoot,
	}, nil
}

func canonicalV1Root(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("root is not a real directory")
	}
	return filepath.Clean(resolved), nil
}

func (inspector *V1InstallationInspector) Inspect(ctx context.Context) (V1Inspection, error) {
	if ctx == nil {
		return V1Inspection{}, fmt.Errorf("context is required")
	}
	if inspector == nil || inspector.workspaceRoot == "" || inspector.stateRoot == "" || inspector.systemRoot == "" {
		return V1Inspection{}, fmt.Errorf("v1 inspector is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return V1Inspection{}, err
	}
	inspection := V1Inspection{
		Report: V1InspectionReport{
			SchemaVersion: V1InspectionSchemaVersion,
			Status:        V1InspectionReady, StateDirectory: v1StateDirectoryName,
			Server:  V1ServerSummary{DNSServers: []string{}},
			Clients: []V1ClientSummary{}, Rulesets: []V1RulesetSummary{},
			Generated: []V1GeneratedArtifact{}, UFW: V1UFWReport{Rules: []V1UFWRule{}},
			Issues: []V1InspectionIssue{},
		},
		rulesets: map[string]v1state.Ruleset{}, privateKeys: map[string][]byte{}, generated: map[string][]byte{},
	}
	present, err := v1RealDirectory(inspector.stateRoot)
	if err != nil {
		inspection.addIssue(V1IssueError, "unsafe_state_directory", "state", v1StateDirectoryName, "v1 state directory is not a real directory")
		inspection.finish()
		return inspection, nil
	}
	if !present {
		inspection.Report.Status = V1InspectionAbsent
		return inspection, nil
	}
	for _, step := range []func(context.Context, *V1InstallationInspector) error{
		inspection.inspectState, inspection.inspectRulesets, inspection.inspectSecrets,
		inspection.inspectGenerated, inspection.inspectSystem,
	} {
		if err := step(ctx, inspector); err != nil {
			inspection.Destroy()
			return V1Inspection{}, err
		}
	}
	inspection.finish()
	return inspection, nil
}

func (inspection *V1Inspection) inspectState(ctx context.Context, inspector *V1InstallationInspector) error {
	data, metadata, err := readV1RegularFile(ctx, filepath.Join(inspector.stateRoot, "state.json"), v1MaximumStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		inspection.addIssue(V1IssueWarning, "state_missing", "state", ".vpnctl/state.json", "v1 state file is missing")
		return nil
	}
	if err != nil {
		inspection.addIssue(V1IssueError, "state_unreadable", "state", ".vpnctl/state.json", v1SafeReadMessage(err))
		return nil
	}
	inspection.Report.StatePresent = true
	if metadata.Mode.Perm() != 0o644 {
		inspection.addIssue(V1IssueWarning, "state_mode_unexpected", "state", ".vpnctl/state.json", "v1 state file mode is not 0644")
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		inspection.addIssue(V1IssueError, "state_malformed", "state", ".vpnctl/state.json", "v1 state is not valid JSON")
		return nil
	}
	inspection.Report.StateSchemaVersion = header.SchemaVersion
	if header.SchemaVersion != v1state.SchemaVersion {
		inspection.addIssue(V1IssueError, "unsupported_state_schema", "state", ".vpnctl/state.json", fmt.Sprintf("v1 state schema %d is unsupported", header.SchemaVersion))
		return nil
	}
	var parsed v1state.State
	if err := decodeV1Strict(data, &parsed); err != nil {
		inspection.addIssue(V1IssueError, "state_malformed", "state", ".vpnctl/state.json", "v1 state shape is malformed or contains unknown fields")
		return nil
	}
	if parsed.Clients == nil {
		parsed.Clients = []v1state.ClientState{}
	}
	inspection.state = parsed
	inspection.validateState()
	return nil
}

var (
	v1ClientIDPattern  = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]*$")
	v1InterfacePattern = regexp.MustCompile("^[A-Za-z0-9_=+.-]{1,15}$")
)

func (inspection *V1Inspection) validateState() {
	if inspection.state.Server == nil {
		inspection.addIssue(V1IssueWarning, "server_missing", "server", ".vpnctl/state.json", "v1 server is not configured")
		return
	}
	server := inspection.state.Server
	inspection.Report.Server = V1ServerSummary{
		Present: true, ID: server.ID, Name: server.Name, PublicEndpoint: server.PublicEndpoint,
		WireGuardInterface: server.WireGuardInterface, WireGuardPort: server.WireGuardPort,
		WireGuardSubnet: server.WireGuardSubnet, WireGuardPublicKey: server.WireGuardPublicKey,
		DNSServers: append([]string{}, server.DNSServers...), ExternalInterface: server.ExternalInterface,
	}
	if err := v1state.ValidateServerConfig(v1state.ServerConfig{
		ID: server.ID, Name: server.Name, PublicEndpoint: server.PublicEndpoint, WireGuardPort: server.WireGuardPort,
		WireGuardInterface: server.WireGuardInterface, WireGuardSubnet: server.WireGuardSubnet,
		DNSServers: append([]string{}, server.DNSServers...), ExternalInterface: server.ExternalInterface,
	}); err != nil {
		inspection.addIssue(V1IssueError, "server_invalid", "server", ".vpnctl/state.json", "v1 server settings are invalid")
	}
	if !v1InterfacePattern.MatchString(server.WireGuardInterface) {
		inspection.addIssue(V1IssueError, "wireguard_interface_unsafe", "server", ".vpnctl/state.json", "v1 WireGuard interface cannot be mapped to a safe system path")
	}
	if err := wireguard.ValidateKey(server.WireGuardPublicKey); err != nil {
		inspection.addIssue(V1IssueError, "server_public_key_invalid", "server", ".vpnctl/state.json", "v1 server public key is invalid")
	}
	_, subnet, _ := net.ParseCIDR(server.WireGuardSubnet)
	seenIDs := map[string]struct{}{}
	seenIPs := map[string]string{}
	for _, client := range inspection.state.Clients {
		summary := V1ClientSummary{
			ID: client.ID, Name: client.Name, Platform: client.Platform, Status: client.Status,
			AssignedIP: client.AssignedIP, WireGuardPublicKey: client.WireGuardPublicKey,
			Tags: append([]string{}, client.Tags...), CreatedAt: client.CreatedAt,
		}
		inspection.Report.Clients = append(inspection.Report.Clients, summary)
		if !v1ClientIDPattern.MatchString(client.ID) {
			inspection.addIssue(V1IssueError, "client_id_invalid", "client", ".vpnctl/state.json", "v1 client has an unsafe or empty ID")
		}
		if _, duplicate := seenIDs[client.ID]; duplicate {
			inspection.addIssue(V1IssueError, "client_id_duplicate", "client", ".vpnctl/state.json", "v1 client IDs are not unique")
		}
		seenIDs[client.ID] = struct{}{}
		switch client.Status {
		case v1state.ClientStatusActive:
			if client.RevokedAt != nil || client.RevocationReason != "" {
				inspection.addIssue(V1IssueError, "client_lifecycle_invalid", "client", ".vpnctl/state.json", "active v1 client contains revocation metadata")
			}
		case v1state.ClientStatusRevoked:
			if client.RevokedAt == nil || client.RevokedAt.IsZero() {
				inspection.addIssue(V1IssueError, "client_lifecycle_invalid", "client", ".vpnctl/state.json", "revoked v1 client lacks revocation time")
			}
		case v1state.ClientStatusDeleted:
		default:
			inspection.addIssue(V1IssueError, "client_status_unsupported", "client", ".vpnctl/state.json", "v1 client status is unsupported")
		}
		if client.CreatedAt.IsZero() {
			inspection.addIssue(V1IssueError, "client_created_at_invalid", "client", ".vpnctl/state.json", "v1 client creation time is missing")
		}
		ip := net.ParseIP(client.AssignedIP)
		if !validV1ClientAddress(subnet, ip) {
			inspection.addIssue(V1IssueError, "client_address_invalid", "client", ".vpnctl/state.json", "v1 client address is invalid or outside the server subnet")
		} else if owner, duplicate := seenIPs[ip.String()]; duplicate {
			inspection.addIssue(V1IssueError, "client_address_duplicate", "client", ".vpnctl/state.json", fmt.Sprintf("v1 clients %s and %s share an address", owner, client.ID))
		} else {
			seenIPs[ip.String()] = client.ID
		}
		if err := wireguard.ValidateKey(client.WireGuardPublicKey); err != nil {
			inspection.addIssue(V1IssueError, "client_public_key_invalid", "client", ".vpnctl/state.json", "v1 client public key is invalid")
		}
	}
	sort.Slice(inspection.Report.Clients, func(i, j int) bool {
		return inspection.Report.Clients[i].ID < inspection.Report.Clients[j].ID
	})
}

func validV1ClientAddress(subnet *net.IPNet, ip net.IP) bool {
	if subnet == nil || ip == nil || ip.To4() == nil || !subnet.Contains(ip) {
		return false
	}
	networkIP := subnet.IP.To4()
	ones, bits := subnet.Mask.Size()
	if networkIP == nil || bits != 32 || ones > 30 {
		return false
	}
	network := uint64(binary.BigEndian.Uint32(networkIP.Mask(subnet.Mask)))
	address := uint64(binary.BigEndian.Uint32(ip.To4()))
	size := uint64(1) << uint(32-ones)
	return address >= network+2 && address <= network+size-2
}

func (inspection *V1Inspection) inspectRulesets(ctx context.Context, inspector *V1InstallationInspector) error {
	directory := filepath.Join(inspector.stateRoot, "rulesets")
	entries, err := readV1Directory(directory)
	if errors.Is(err, fs.ErrNotExist) {
		inspection.addIssue(V1IssueWarning, "rulesets_missing", "ruleset", ".vpnctl/rulesets", "v1 ruleset directory is missing")
		return nil
	}
	if err != nil {
		inspection.addIssue(V1IssueError, "rulesets_unsafe", "ruleset", ".vpnctl/rulesets", "v1 ruleset directory is unreadable or unsafe")
		return nil
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		logical := filepath.ToSlash(filepath.Join(".vpnctl", "rulesets", entry.Name()))
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			inspection.addIssue(V1IssueError, "ruleset_entry_unsupported", "ruleset", logical, "v1 ruleset entry is not a regular JSON file")
			continue
		}
		data, _, err := readV1RegularFile(ctx, filepath.Join(directory, entry.Name()), v1MaximumRulesetBytes)
		if err != nil {
			inspection.addIssue(V1IssueError, "ruleset_unreadable", "ruleset", logical, v1SafeReadMessage(err))
			continue
		}
		var ruleset v1state.Ruleset
		if err := decodeV1Strict(data, &ruleset); err != nil || v1state.ValidateRuleset(ruleset) != nil {
			inspection.addIssue(V1IssueError, "ruleset_invalid", "ruleset", logical, "v1 ruleset is malformed or unsupported")
			continue
		}
		if strings.TrimSuffix(entry.Name(), ".json") != ruleset.ID {
			inspection.addIssue(V1IssueError, "ruleset_filename_mismatch", "ruleset", logical, "v1 ruleset filename does not match its ID")
			continue
		}
		if _, duplicate := inspection.rulesets[ruleset.ID]; duplicate {
			inspection.addIssue(V1IssueError, "ruleset_id_duplicate", "ruleset", logical, "v1 ruleset ID is duplicated")
			continue
		}
		inspection.rulesets[ruleset.ID] = ruleset
		inspection.Report.Rulesets = append(inspection.Report.Rulesets, V1RulesetSummary{
			ID: ruleset.ID, Name: ruleset.Name, Type: ruleset.Type, DomainCount: len(ruleset.Domains),
		})
	}
	sort.Slice(inspection.Report.Rulesets, func(i, j int) bool {
		return inspection.Report.Rulesets[i].ID < inspection.Report.Rulesets[j].ID
	})
	if _, ok := inspection.rulesets["default"]; !ok {
		inspection.addIssue(V1IssueWarning, "default_ruleset_missing", "ruleset", ".vpnctl/rulesets/default.json", "v1 default ruleset is missing")
	}
	return nil
}

func (inspection *V1Inspection) inspectSecrets(ctx context.Context, inspector *V1InstallationInspector) error {
	if !inspection.Report.StatePresent || inspection.Report.StateSchemaVersion != v1state.SchemaVersion {
		return inspection.inspectUnexpectedSecretTree(inspector, nil)
	}
	expected := map[string]struct{}{"server_private.key": {}}
	if inspection.state.Server != nil {
		inspection.inspectPrivateKey(ctx, inspector, "server", "", inspection.state.Server.WireGuardPublicKey)
	}
	for _, client := range inspection.state.Clients {
		if !v1ClientIDPattern.MatchString(client.ID) {
			continue
		}
		relative := filepath.Join("clients", client.ID+".key")
		expected[relative] = struct{}{}
		if client.Status == v1state.ClientStatusDeleted {
			if present, _ := v1PathPresent(filepath.Join(inspector.stateRoot, "secrets", relative)); present {
				inspection.addIssue(V1IssueWarning, "deleted_client_key_present", "secret", filepath.ToSlash(filepath.Join(".vpnctl", "secrets", relative)), "deleted v1 client still has a private-key file")
			}
			continue
		}
		inspection.inspectPrivateKey(ctx, inspector, "client", client.ID, client.WireGuardPublicKey)
	}
	return inspection.inspectUnexpectedSecretTree(inspector, expected)
}

func (inspection *V1Inspection) inspectPrivateKey(ctx context.Context, inspector *V1InstallationInspector, kind, clientID, publicKey string) {
	relative := "server_private.key"
	keyID := "server"
	if kind == "client" {
		relative = filepath.Join("clients", clientID+".key")
		keyID = "client:" + clientID
	}
	logical := filepath.ToSlash(filepath.Join(".vpnctl", "secrets", relative))
	data, metadata, err := readV1RegularFile(ctx, filepath.Join(inspector.stateRoot, "secrets", relative), v1MaximumSecretBytes)
	present, valid, matches := err == nil, false, false
	switch {
	case errors.Is(err, fs.ErrNotExist):
		inspection.addIssue(V1IssueWarning, kind+"_private_key_missing", "secret", logical, kind+" private key is missing")
	case err != nil:
		inspection.addIssue(V1IssueError, kind+"_private_key_unsafe", "secret", logical, v1SafeReadMessage(err))
	default:
		if metadata.Mode.Perm() != 0o600 {
			inspection.addIssue(V1IssueWarning, kind+"_private_key_mode", "secret", logical, kind+" private key mode is not 0600")
		}
		key := bytes.TrimSpace(data)
		valid = wireguard.ValidateKey(string(key)) == nil
		if !valid {
			inspection.addIssue(V1IssueError, kind+"_private_key_invalid", "secret", logical, kind+" private key is invalid")
		} else {
			inspection.privateKeys[keyID] = append([]byte(nil), key...)
			derived, deriveErr := v1WireGuardPublicKey(key)
			matches = deriveErr == nil && derived == publicKey
			if !matches {
				inspection.addIssue(V1IssueError, kind+"_key_pair_mismatch", "secret", logical, kind+" private key does not match the state public key")
			}
		}
		clear(data)
	}
	if kind == "server" {
		inspection.Report.Server.PrivateKeyPresent = present
		inspection.Report.Server.PrivateKeyValid = valid
		inspection.Report.Server.KeyPairMatches = matches
		return
	}
	for index := range inspection.Report.Clients {
		if inspection.Report.Clients[index].ID == clientID {
			inspection.Report.Clients[index].PrivateKeyPresent = present
			inspection.Report.Clients[index].PrivateKeyValid = valid
			inspection.Report.Clients[index].KeyPairMatches = matches
			return
		}
	}
}

func v1WireGuardPublicKey(privateKey []byte) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(privateKey))
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid private key")
	}
	public, err := curve25519.X25519(decoded, curve25519.Basepoint)
	clear(decoded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

func (inspection *V1Inspection) inspectUnexpectedSecretTree(inspector *V1InstallationInspector, expected map[string]struct{}) error {
	root := filepath.Join(inspector.stateRoot, "secrets")
	entries, err := readV1Directory(root)
	if errors.Is(err, fs.ErrNotExist) {
		inspection.addIssue(V1IssueWarning, "secrets_missing", "secret", ".vpnctl/secrets", "v1 secret directory is missing")
		return nil
	}
	if err != nil {
		inspection.addIssue(V1IssueError, "secrets_unsafe", "secret", ".vpnctl/secrets", "v1 secret directory is unreadable or unsafe")
		return nil
	}
	for _, entry := range entries {
		if entry.Name() == "clients" {
			clients, clientErr := readV1Directory(filepath.Join(root, "clients"))
			if errors.Is(clientErr, fs.ErrNotExist) {
				inspection.addIssue(V1IssueWarning, "client_secrets_missing", "secret", ".vpnctl/secrets/clients", "v1 client secret directory is missing")
				continue
			}
			if clientErr != nil {
				inspection.addIssue(V1IssueError, "client_secrets_unsafe", "secret", ".vpnctl/secrets/clients", "v1 client secret directory is unreadable or unsafe")
				continue
			}
			for _, clientEntry := range clients {
				relative := filepath.Join("clients", clientEntry.Name())
				_, associated := expected[relative]
				if !associated || clientEntry.Type()&os.ModeSymlink != 0 || !clientEntry.Type().IsRegular() {
					inspection.addIssue(V1IssueWarning, "unexpected_secret_entry", "secret", filepath.ToSlash(filepath.Join(".vpnctl", "secrets", relative)), "v1 secret entry is not associated with a retained client")
				}
			}
			continue
		}
		_, associated := expected[entry.Name()]
		if !associated || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			inspection.addIssue(V1IssueWarning, "unexpected_secret_entry", "secret", filepath.ToSlash(filepath.Join(".vpnctl", "secrets", entry.Name())), "v1 secret entry is not an expected regular file")
		}
	}
	return nil
}

func (inspection *V1Inspection) inspectGenerated(ctx context.Context, inspector *V1InstallationInspector) error {
	total := int64(0)
	clientIDs := make([]string, 0, len(inspection.Report.Clients))
	for _, client := range inspection.Report.Clients {
		clientIDs = append(clientIDs, client.ID)
	}
	for _, kind := range []string{"wireguard", "mihomo", "delivery"} {
		root := filepath.Join(inspector.stateRoot, "generated", kind)
		entries, err := readV1Directory(root)
		logicalRoot := filepath.ToSlash(filepath.Join(".vpnctl", "generated", kind))
		if errors.Is(err, fs.ErrNotExist) {
			inspection.addIssue(V1IssueWarning, "generated_directory_missing", "generated", logicalRoot, "v1 generated-artifact directory is missing")
			continue
		}
		if err != nil {
			inspection.addIssue(V1IssueError, "generated_directory_unsafe", "generated", logicalRoot, "v1 generated-artifact directory is unreadable or unsafe")
			continue
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			logical := filepath.ToSlash(filepath.Join(".vpnctl", "generated", kind, entry.Name()))
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || !entry.Type().IsRegular() {
				inspection.addIssue(V1IssueError, "generated_entry_unsupported", "generated", logical, "v1 generated artifact is not a regular file")
				continue
			}
			if len(inspection.Report.Generated) >= v1MaximumGeneratedFiles {
				inspection.addIssue(V1IssueError, "generated_file_limit", "generated", logicalRoot, "v1 generated artifact count exceeds the inspection limit")
				return nil
			}
			data, metadata, err := readV1RegularFile(ctx, filepath.Join(root, entry.Name()), v1MaximumGeneratedBytes)
			if err != nil {
				inspection.addIssue(V1IssueError, "generated_entry_unreadable", "generated", logical, v1SafeReadMessage(err))
				continue
			}
			total += metadata.Size
			if total > v1MaximumGeneratedTotal {
				clear(data)
				inspection.addIssue(V1IssueError, "generated_total_limit", "generated", logicalRoot, "v1 generated artifacts exceed the total inspection limit")
				return nil
			}
			relative := filepath.ToSlash(filepath.Join("generated", kind, entry.Name()))
			inspection.generated[relative] = data
			inspection.Report.Generated = append(inspection.Report.Generated, V1GeneratedArtifact{
				Path: logical, Kind: kind, ClientID: v1GeneratedClientID(entry.Name(), clientIDs),
				Bytes: metadata.Size, Mode: uint32(metadata.Mode.Perm()),
			})
		}
	}
	sort.Slice(inspection.Report.Generated, func(i, j int) bool {
		return inspection.Report.Generated[i].Path < inspection.Report.Generated[j].Path
	})
	return nil
}

func v1GeneratedClientID(name string, clientIDs []string) string {
	for _, id := range clientIDs {
		if name == id+".conf" || name == id+".clash.yaml" {
			return id
		}
	}
	return ""
}

func (inspection *V1Inspection) inspectSystem(ctx context.Context, inspector *V1InstallationInspector) error {
	inspection.Report.ForwardingConfig = inspection.inspectSystemArtifact(
		ctx, inspector, "/etc/sysctl.d/99-vpnctl.conf", []byte("net.ipv4.ip_forward=1\n"), 0o644, "forwarding_config",
	)
	if inspection.state.Server != nil && v1InterfacePattern.MatchString(inspection.state.Server.WireGuardInterface) {
		logical := filepath.ToSlash(filepath.Join("/etc/wireguard", inspection.state.Server.WireGuardInterface+".conf"))
		expected := inspection.expectedWireGuardConfig()
		inspection.Report.WireGuardConfig = inspection.inspectSystemArtifact(ctx, inspector, logical, expected, 0o600, "wireguard_config")
		clear(expected)
		if inspection.Report.WireGuardConfig.Present && inspection.Report.WireGuardConfig.Regular {
			data, _, err := readV1SystemRegularFile(ctx, inspector.systemRoot, logical, v1MaximumSystemFileBytes)
			if err == nil {
				inspection.systemWireGuard = data
			}
		}
	}
	inspection.inspectUFW(ctx, inspector)
	return nil
}

func (inspection *V1Inspection) expectedWireGuardConfig() []byte {
	if inspection.state.Server == nil {
		return nil
	}
	private := inspection.privateKeys["server"]
	if len(private) == 0 {
		return nil
	}
	address, err := wireguard.ServerAddress(inspection.state.Server.WireGuardSubnet)
	if err != nil {
		return nil
	}
	peers := make([]wireguard.ServerPeer, 0, len(inspection.state.Clients))
	for _, client := range inspection.state.Clients {
		peers = append(peers, wireguard.ServerPeer{
			Name: client.ID, PublicKey: client.WireGuardPublicKey,
			AllowedIPs: client.AssignedIP + "/32", Status: client.Status,
		})
	}
	rendered, err := wireguard.RenderServerConfig(wireguard.ServerConfig{
		InterfaceName: inspection.state.Server.WireGuardInterface,
		Address:       address, ListenPort: inspection.state.Server.WireGuardPort,
		PrivateKey: string(private), ExternalInterface: inspection.state.Server.ExternalInterface,
		Peers: peers,
	})
	if err != nil {
		return nil
	}
	return []byte(rendered)
}

func (inspection *V1Inspection) inspectSystemArtifact(
	ctx context.Context,
	inspector *V1InstallationInspector,
	logical string,
	expected []byte,
	wantMode os.FileMode,
	code string,
) V1SystemArtifact {
	result := V1SystemArtifact{Path: logical}
	data, metadata, err := readV1SystemRegularFile(ctx, inspector.systemRoot, logical, v1MaximumSystemFileBytes)
	if errors.Is(err, fs.ErrNotExist) {
		inspection.addIssue(V1IssueWarning, code+"_missing", "system", logical, "expected v1 system artifact is missing")
		return result
	}
	if err != nil {
		inspection.addIssue(V1IssueError, code+"_unsafe", "system", logical, v1SafeReadMessage(err))
		return result
	}
	result.Present, result.Regular = true, true
	result.Mode, result.Bytes = uint32(metadata.Mode.Perm()), metadata.Size
	result.MatchesState = len(expected) > 0 && bytes.Equal(data, expected)
	if metadata.Mode.Perm() != wantMode {
		inspection.addIssue(V1IssueWarning, code+"_mode", "system", logical, "v1 system artifact mode differs from the expected installer mode")
	}
	if len(expected) == 0 {
		inspection.addIssue(V1IssueWarning, code+"_unverifiable", "system", logical, "v1 system artifact cannot be compared until state and keys are valid")
	} else if !result.MatchesState {
		inspection.addIssue(V1IssueWarning, code+"_drift", "system", logical, "v1 system artifact differs from the inspected source state")
	}
	clear(data)
	return result
}

func (inspection *V1Inspection) inspectUFW(ctx context.Context, inspector *V1InstallationInspector) {
	configData, _, configErr := readV1SystemRegularFile(ctx, inspector.systemRoot, "/etc/ufw/ufw.conf", v1MaximumSystemFileBytes)
	if errors.Is(configErr, fs.ErrNotExist) {
		inspection.addIssue(V1IssueWarning, "ufw_config_missing", "ufw", "/etc/ufw/ufw.conf", "v1 UFW configuration is missing")
	} else if configErr != nil {
		inspection.addIssue(V1IssueError, "ufw_config_unsafe", "ufw", "/etc/ufw/ufw.conf", v1SafeReadMessage(configErr))
	} else {
		inspection.Report.UFW.ConfigPresent = true
		if enabled, ok := parseV1UFWEnabled(configData); ok {
			inspection.Report.UFW.Enabled = &enabled
		} else {
			inspection.addIssue(V1IssueWarning, "ufw_enabled_unknown", "ufw", "/etc/ufw/ufw.conf", "v1 UFW enabled state is not recognizable")
		}
	}
	for _, source := range []struct {
		logical string
		family  string
	}{
		{logical: "/etc/ufw/user.rules", family: "ipv4"},
		{logical: "/etc/ufw/user6.rules", family: "ipv6"},
	} {
		data, _, err := readV1SystemRegularFile(ctx, inspector.systemRoot, source.logical, v1MaximumSystemFileBytes)
		if errors.Is(err, fs.ErrNotExist) {
			inspection.addIssue(V1IssueWarning, "ufw_rules_missing", "ufw", source.logical, "v1 UFW rule file is missing")
			continue
		}
		if err != nil {
			inspection.addIssue(V1IssueError, "ufw_rules_unsafe", "ufw", source.logical, v1SafeReadMessage(err))
			continue
		}
		for _, rule := range parseV1UFWRules(data, source.family) {
			switch {
			case inspection.state.Server != nil && rule.Action == "allow" && rule.Direction == "in" &&
				rule.Protocol == "udp" && rule.Port == inspection.state.Server.WireGuardPort:
				rule.Classification = "wireguard"
			case rule.Action == "allow" && rule.Direction == "in" && rule.Protocol == "tcp":
				rule.Classification = "ssh_candidate"
			default:
				rule.Classification = "unrelated"
			}
			inspection.Report.UFW.Rules = append(inspection.Report.UFW.Rules, rule)
		}
	}
	sort.Slice(inspection.Report.UFW.Rules, func(i, j int) bool {
		left, right := inspection.Report.UFW.Rules[i], inspection.Report.UFW.Rules[j]
		if left.Family != right.Family {
			return left.Family < right.Family
		}
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		return left.Action < right.Action
	})
	for _, rule := range inspection.Report.UFW.Rules {
		if rule.Classification == "ssh_candidate" {
			inspection.addIssue(V1IssueInfo, "ufw_ssh_ownership_ambiguous", "ufw", "", "v1 did not persist the SSH port, so TCP allow-rule ownership requires migration review")
			break
		}
	}
}

func parseV1UFWEnabled(data []byte) (bool, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key != "ENABLED" {
			continue
		}
		switch strings.ToLower(strings.Trim(strings.TrimSpace(value), "\"")) {
		case "yes":
			return true, true
		case "no":
			return false, true
		default:
			return false, false
		}
	}
	return false, false
}

func parseV1UFWRules(data []byte, family string) []V1UFWRule {
	rules := []V1UFWRule{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "### tuple ### ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "### tuple ### "))
		if len(fields) < 4 {
			continue
		}
		action, protocol, portText, direction := fields[0], fields[1], fields[2], fields[len(fields)-1]
		if action != "allow" && action != "deny" && action != "reject" && action != "limit" {
			continue
		}
		if protocol != "tcp" && protocol != "udp" && protocol != "any" {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || direction != "in" && direction != "out" {
			continue
		}
		rules = append(rules, V1UFWRule{
			Family: family, Action: action, Protocol: protocol, Port: port, Direction: direction,
		})
	}
	return rules
}

func (inspection *V1Inspection) addIssue(severity V1IssueSeverity, code, scope, path, message string) {
	inspection.Report.Issues = append(inspection.Report.Issues, V1InspectionIssue{
		Severity: severity, Code: code, Scope: scope, Path: path, Message: message,
	})
}

func (inspection *V1Inspection) finish() {
	status := V1InspectionReady
	unsupported := false
	for _, issue := range inspection.Report.Issues {
		if issue.Code == "unsupported_state_schema" {
			unsupported = true
		}
		switch issue.Severity {
		case V1IssueError:
			status = V1InspectionInvalid
		case V1IssueWarning:
			if status == V1InspectionReady {
				status = V1InspectionPartial
			}
		}
	}
	if unsupported {
		status = V1InspectionUnsupported
	}
	inspection.Report.Status = status
	sort.Slice(inspection.Report.Issues, func(i, j int) bool {
		left, right := inspection.Report.Issues[i], inspection.Report.Issues[j]
		if left.Scope != right.Scope {
			return left.Scope < right.Scope
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		return left.Code < right.Code
	})
}

type v1FileMetadata struct {
	Mode os.FileMode
	Size int64
}

func readV1RegularFile(ctx context.Context, path string, limit int64) ([]byte, v1FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, v1FileMetadata{}, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, v1FileMetadata{}, os.NewSyscallError("open", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, v1FileMetadata{}, fmt.Errorf("open returned no file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, v1FileMetadata{}, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, v1FileMetadata{}, fmt.Errorf("file is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, v1FileMetadata{}, fmt.Errorf("file changed or could not be read")
	}
	return data, v1FileMetadata{Mode: info.Mode(), Size: info.Size()}, nil
}

func readV1SystemRegularFile(ctx context.Context, root, logical string, limit int64) ([]byte, v1FileMetadata, error) {
	clean := filepath.Clean(logical)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return nil, v1FileMetadata{}, fmt.Errorf("system path is invalid")
	}
	relative := strings.TrimPrefix(clean, string(filepath.Separator))
	parts := strings.Split(relative, string(filepath.Separator))
	parent := root
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, v1FileMetadata{}, fmt.Errorf("system path is invalid")
		}
		parent = filepath.Join(parent, part)
		present, err := v1RealDirectory(parent)
		if err != nil {
			return nil, v1FileMetadata{}, err
		}
		if !present {
			return nil, v1FileMetadata{}, fs.ErrNotExist
		}
	}
	return readV1RegularFile(ctx, filepath.Join(parent, parts[len(parts)-1]), limit)
}

func readV1Directory(path string) ([]fs.DirEntry, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, os.NewSyscallError("open directory", err)
	}
	directory := os.NewFile(uintptr(fd), filepath.Base(path))
	if directory == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open returned no directory")
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("path is not a real directory")
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func v1RealDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("path is not a real directory")
	}
	return true, nil
}

func v1PathPresent(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func decodeV1Strict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}

func v1SafeReadMessage(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "v1 artifact is not readable"
	case errors.Is(err, fs.ErrNotExist):
		return "v1 artifact is missing"
	default:
		return "v1 artifact is unsafe, oversized, or changed during inspection"
	}
}
