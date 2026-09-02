package model

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	namePattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	secretRefPattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	hashPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	serialPattern      = regexp.MustCompile(`^[0-9a-f]{1,32}$`)
	componentPattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
	errorCodePattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
	protocolPattern    = regexp.MustCompile(`^[1-9][0-9]*\.[0-9]+$`)
)

func (state State) Validate() error {
	if err := validateSchema("state", state.SchemaVersion, StateSchemaVersion); err != nil {
		return err
	}
	if state.Generation == 0 {
		return invalid("generation", "must be positive")
	}
	if err := state.Host.Validate(); err != nil {
		return wrap("host", err)
	}
	if err := state.Components.Validate(); err != nil {
		return wrap("components", err)
	}
	if state.Components.TargetOS != state.Host.OS+" "+state.Host.OSVersion || state.Components.TargetArchitecture != state.Host.Architecture {
		return invalid("components", "target does not match host")
	}
	if state.SchemaVersion < state.Components.StateSchemaMinimum || state.SchemaVersion > state.Components.StateSchemaMaximum {
		return invalid("components", "state schema %d is outside supported range", state.SchemaVersion)
	}
	if state.Nodes == nil || state.Clients == nil || state.Presets == nil || state.Policies == nil || state.Transports == nil || state.Exposes == nil || state.Certificates == nil || state.Operations == nil || state.Logging == nil || state.Backups == nil {
		return invalid("state", "all resource collections must be present as JSON arrays")
	}

	nodes := make(map[string]Node, len(state.Nodes))
	nodeNames := make(map[string]string, len(state.Nodes))
	for index, node := range state.Nodes {
		if err := node.Validate(); err != nil {
			return wrap(indexPath("nodes", index), err)
		}
		if _, duplicate := nodes[node.ID]; duplicate {
			return invalid(indexPath("nodes", index)+".id", "duplicates node %s", node.ID)
		}
		nodes[node.ID] = node
		if node.Lifecycle != LifecycleDeleted {
			key := strings.ToLower(node.Name)
			if prior, duplicate := nodeNames[key]; duplicate {
				return invalid(indexPath("nodes", index)+".name", "duplicates active node name owned by %s", prior)
			}
			nodeNames[key] = node.ID
		}
	}
	clients := make(map[string]Client, len(state.Clients))
	clientNames := make(map[string]string, len(state.Clients))
	for index, client := range state.Clients {
		if err := client.Validate(); err != nil {
			return wrap(indexPath("clients", index), err)
		}
		if _, duplicate := clients[client.ID]; duplicate {
			return invalid(indexPath("clients", index)+".id", "duplicates client %s", client.ID)
		}
		clients[client.ID] = client
		if client.Lifecycle != LifecycleDeleted {
			key := strings.ToLower(client.Name)
			if prior, duplicate := clientNames[key]; duplicate {
				return invalid(indexPath("clients", index)+".name", "duplicates active client name owned by %s", prior)
			}
			clientNames[key] = client.ID
		}
	}

	presets := make(map[string]Preset, len(state.Presets))
	for index, preset := range state.Presets {
		if err := preset.Validate(); err != nil {
			return wrap(indexPath("presets", index), err)
		}
		key := strings.ToLower(preset.Name)
		if _, duplicate := presets[key]; duplicate {
			return invalid(indexPath("presets", index)+".name", "duplicates preset %s", preset.Name)
		}
		presets[key] = preset
	}

	policies := make(map[string]Policy, len(state.Policies))
	for index, policy := range state.Policies {
		if err := policy.Validate(); err != nil {
			return wrap(indexPath("policies", index), err)
		}
		key := targetKey(policy.TargetKind, policy.TargetID)
		if _, duplicate := policies[key]; duplicate {
			return invalid(indexPath("policies", index), "duplicates policy target %s", key)
		}
		if !targetExists(policy.TargetKind, policy.TargetID, nodes, clients) {
			return invalid(indexPath("policies", index)+".target_id", "references an unknown %s", policy.TargetKind)
		}
		if state.Host.Role == RoleGateway {
			for _, name := range policy.PresetNames {
				if _, found := presets[strings.ToLower(name)]; !found {
					return invalid(indexPath("policies", index)+".preset_names", "references unknown preset %s", name)
				}
			}
		}
		policies[key] = policy
	}
	for _, node := range state.Nodes {
		if policy, found := policies[targetKey(TargetNode, node.ID)]; found {
			if !equalStringSet(policy.PresetNames, node.AssignedPresets) {
				return invalid("nodes", "assigned presets for node %s differ from its policy", node.ID)
			}
		} else if len(node.AssignedPresets) != 0 {
			return invalid("nodes", "node %s has assigned presets without a policy", node.ID)
		}
	}
	for _, client := range state.Clients {
		if policy, found := policies[targetKey(TargetClient, client.ID)]; found {
			if !equalStringSet(policy.PresetNames, client.AssignedPresets) {
				return invalid("clients", "assigned presets for client %s differ from its policy", client.ID)
			}
		} else if len(client.AssignedPresets) != 0 {
			return invalid("clients", "client %s has assigned presets without a policy", client.ID)
		}
	}

	transportKinds := make(map[string]map[TransportKind]struct{})
	transportStates := make(map[string]map[TransportKind]TransportState)
	for index, transport := range state.Transports {
		if err := transport.Validate(); err != nil {
			return wrap(indexPath("transports", index), err)
		}
		if !targetExists(transport.OwnerKind, transport.OwnerID, nodes, clients) {
			return invalid(indexPath("transports", index)+".owner_id", "references an unknown %s", transport.OwnerKind)
		}
		owner := targetKey(transport.OwnerKind, transport.OwnerID)
		if transportKinds[owner] == nil {
			transportKinds[owner] = make(map[TransportKind]struct{})
			transportStates[owner] = make(map[TransportKind]TransportState)
		}
		if _, duplicate := transportKinds[owner][transport.Kind]; duplicate {
			return invalid(indexPath("transports", index)+".kind", "duplicates %s transport for %s", transport.Kind, owner)
		}
		transportKinds[owner][transport.Kind] = struct{}{}
		transportStates[owner][transport.Kind] = transport.State
	}
	for _, node := range state.Nodes {
		if err := validateActiveTransport(TargetNode, node.ID, node.ActiveTransport, node.Lifecycle, transportStates); err != nil {
			return err
		}
	}
	for _, client := range state.Clients {
		if err := validateActiveTransport(TargetClient, client.ID, client.ActiveTransport, client.Lifecycle, transportStates); err != nil {
			return err
		}
	}

	exposeIDs := make(map[string]struct{}, len(state.Exposes))
	exposeRoutes := make(map[string]string, len(state.Exposes))
	for index, expose := range state.Exposes {
		if err := expose.Validate(); err != nil {
			return wrap(indexPath("exposes", index), err)
		}
		if _, found := nodes[expose.NodeID]; !found {
			return invalid(indexPath("exposes", index)+".node_id", "references an unknown node")
		}
		if node := nodes[expose.NodeID]; node.Lifecycle != LifecycleActive && expose.State != ExposeDisabled {
			return invalid(indexPath("exposes", index)+".state", "non-active node expose must be disabled")
		}
		if _, duplicate := exposeIDs[expose.ID]; duplicate {
			return invalid(indexPath("exposes", index)+".id", "duplicates expose %s", expose.ID)
		}
		exposeIDs[expose.ID] = struct{}{}
		if expose.State != ExposeDisabled {
			key := string(expose.RouteMode) + ":" + expose.Path
			if prior, duplicate := exposeRoutes[key]; duplicate {
				return invalid(indexPath("exposes", index)+".path", "duplicates active route owned by %s", prior)
			}
			exposeRoutes[key] = expose.ID
		}
	}

	certificateIDs := make(map[string]struct{}, len(state.Certificates))
	for index, certificate := range state.Certificates {
		if err := certificate.Validate(); err != nil {
			return wrap(indexPath("certificates", index), err)
		}
		if _, duplicate := certificateIDs[certificate.ID]; duplicate {
			return invalid(indexPath("certificates", index)+".id", "duplicates certificate %s", certificate.ID)
		}
		certificateIDs[certificate.ID] = struct{}{}
		if certificate.OwnerKind == "node" {
			if _, found := nodes[certificate.OwnerID]; !found {
				return invalid(indexPath("certificates", index)+".owner_id", "references an unknown node")
			}
		} else if certificate.OwnerKind != "host" || certificate.OwnerID != state.Host.ID {
			return invalid(indexPath("certificates", index)+".owner_id", "does not reference this host")
		}
	}

	operationIDs := make(map[string]struct{}, len(state.Operations))
	for index, operation := range state.Operations {
		if err := operation.Validate(); err != nil {
			return wrap(indexPath("operations", index), err)
		}
		if _, duplicate := operationIDs[operation.ID]; duplicate {
			return invalid(indexPath("operations", index)+".id", "duplicates operation %s", operation.ID)
		}
		operationIDs[operation.ID] = struct{}{}
	}
	loggingIDs := make(map[string]struct{}, len(state.Logging))
	for index, session := range state.Logging {
		if err := session.Validate(); err != nil {
			return wrap(indexPath("logging", index), err)
		}
		if _, duplicate := loggingIDs[session.ID]; duplicate {
			return invalid(indexPath("logging", index)+".id", "duplicates logging session %s", session.ID)
		}
		loggingIDs[session.ID] = struct{}{}
	}
	backupIDs := make(map[string]struct{}, len(state.Backups))
	for index, backup := range state.Backups {
		if err := backup.Validate(); err != nil {
			return wrap(indexPath("backups", index), err)
		}
		if _, duplicate := backupIDs[backup.ID]; duplicate {
			return invalid(indexPath("backups", index)+".id", "duplicates backup %s", backup.ID)
		}
		backupIDs[backup.ID] = struct{}{}
	}

	switch state.Host.Role {
	case RoleGateway:
		if len(state.Nodes) > 0 {
			for index, node := range state.Nodes {
				if node.Gateway != nil {
					return invalid(indexPath("nodes", index)+".gateway", "gateway-authoritative node must not embed local gateway trust")
				}
			}
		}
	case RoleNode:
		if len(state.Nodes) > 1 {
			return invalid("nodes", "node host may contain at most one local node identity")
		}
		if len(state.Clients) != 0 || len(state.Presets) != 0 || len(state.Backups) != 0 {
			return invalid("host.role", "node state cannot contain gateway client, preset, or backup collections")
		}
		if len(state.Nodes) == 1 && state.Nodes[0].Gateway == nil {
			return invalid("nodes[0].gateway", "joined local node requires gateway trust")
		}
		localID := ""
		if len(state.Nodes) == 1 {
			localID = state.Nodes[0].ID
		}
		for index, policy := range state.Policies {
			if policy.TargetKind != TargetNode || policy.TargetID != localID {
				return invalid(indexPath("policies", index), "node state may contain only its local policy")
			}
		}
		for index, transport := range state.Transports {
			if transport.OwnerKind != TargetNode || transport.OwnerID != localID {
				return invalid(indexPath("transports", index), "node state may contain only its local transports")
			}
		}
		for index, expose := range state.Exposes {
			if expose.NodeID != localID {
				return invalid(indexPath("exposes", index), "node state may contain only its local exposes")
			}
		}
	}
	return nil
}

func (host Host) Validate() error {
	if err := validateSchema("host", host.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateUUID("id", host.ID); err != nil {
		return err
	}
	if host.Role != RoleGateway && host.Role != RoleNode {
		return invalid("role", "unsupported value %q", host.Role)
	}
	if host.OS != "ubuntu" || host.OSVersion != "24.04" || host.Architecture != "amd64" {
		return invalid("platform", "must be ubuntu 24.04 amd64")
	}
	if err := validateTime("initialized_at", host.InitializedAt); err != nil {
		return err
	}
	if host.ManagedSwap != nil {
		if !filepath.IsAbs(host.ManagedSwap.Path) || host.ManagedSwap.SizeBytes <= 0 {
			return invalid("managed_swap", "requires an absolute path and positive size")
		}
	}
	if host.Role == RoleGateway {
		if err := validateIPv4("public_ipv4", host.PublicIPv4); err != nil {
			return err
		}
		if strings.TrimSpace(host.ExternalInterface) == "" || strings.ContainsAny(host.ExternalInterface, " /\t\r\n") {
			return invalid("external_interface", "must be a non-empty interface name")
		}
		if host.SSHPort < 1 || host.SSHPort > 65535 {
			return invalid("ssh_port", "must be between 1 and 65535")
		}
		clientPrefix, err := validateIPv4Prefix("client_cidr", host.ClientCIDR)
		if err != nil {
			return err
		}
		nodePrefix, err := validateIPv4Prefix("node_cidr", host.NodeCIDR)
		if err != nil {
			return err
		}
		if clientPrefix.Overlaps(nodePrefix) {
			return invalid("client_cidr", "overlaps node_cidr")
		}
	} else if host.PublicIPv4 != "" || host.ExternalInterface != "" || host.SSHPort != 0 || host.ClientCIDR != "" || host.NodeCIDR != "" {
		return invalid("role", "node host contains gateway-only network fields")
	}
	return nil
}

func (node Node) Validate() error {
	if err := validateResource("node", node.SchemaVersion, node.ID, node.Name, node.Lifecycle, node.OverlayIPv4, node.CredentialGeneration, node.ActiveTransport, node.CreatedAt, node.RevokedAt); err != nil {
		return err
	}
	if err := validateUniqueNames("assigned_presets", node.AssignedPresets); err != nil {
		return err
	}
	if node.AssignedPresets == nil {
		return invalid("assigned_presets", "must be present as a JSON array")
	}
	if node.Gateway != nil {
		if err := node.Gateway.Validate(); err != nil {
			return wrap("gateway", err)
		}
	}
	return nil
}

func (trust GatewayTrust) Validate() error {
	if err := validateIPv4("public_ipv4", trust.PublicIPv4); err != nil {
		return err
	}
	if err := validateFingerprint("enrollment_fingerprint", trust.EnrollmentFingerprint); err != nil {
		return err
	}
	if len(trust.ControlCAFingerprints) == 0 || len(trust.ControlCAFingerprints) > 2 {
		return invalid("control_ca_fingerprints", "must contain one or two fingerprints")
	}
	seen := make(map[string]struct{}, len(trust.ControlCAFingerprints))
	for index, fingerprint := range trust.ControlCAFingerprints {
		if err := validateFingerprint(indexPath("control_ca_fingerprints", index), fingerprint); err != nil {
			return err
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			return invalid(indexPath("control_ca_fingerprints", index), "duplicates a fingerprint")
		}
		seen[fingerprint] = struct{}{}
	}
	if trust.LastKnownGatewayGeneration == 0 {
		return invalid("last_known_gateway_generation", "must be positive")
	}
	if trust.PendingRequestID != "" {
		if err := validateUUID("pending_request_id", trust.PendingRequestID); err != nil {
			return err
		}
	}
	return nil
}

func (client Client) Validate() error {
	if err := validateResource("client", client.SchemaVersion, client.ID, client.Name, client.Lifecycle, client.OverlayIPv4, client.CredentialGeneration, client.ActiveTransport, client.CreatedAt, client.RevokedAt); err != nil {
		return err
	}
	if strings.TrimSpace(client.Platform) == "" || len(client.Platform) > 63 {
		return invalid("platform", "must be non-empty and at most 63 bytes")
	}
	if client.AssignedPresets == nil {
		return invalid("assigned_presets", "must be present as a JSON array")
	}
	return validateUniqueNames("assigned_presets", client.AssignedPresets)
}

func (preset Preset) Validate() error {
	if err := validateSchema("preset", preset.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateName("name", preset.Name); err != nil {
		return err
	}
	if err := validateHash("source_hash", preset.SourceHash); err != nil {
		return err
	}
	if err := validateHash("effective_hash", preset.EffectiveHash); err != nil {
		return err
	}
	if preset.Generation == 0 {
		return invalid("generation", "must be positive")
	}
	if err := validateTime("applied_at", preset.AppliedAt); err != nil {
		return err
	}
	if len(preset.Selectors) == 0 {
		return invalid("selectors", "must not be empty")
	}
	return validateSelectors(preset.Selectors)
}

func (policy Policy) Validate() error {
	if err := validateSchema("policy", policy.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if policy.TargetKind != TargetNode && policy.TargetKind != TargetClient {
		return invalid("target_kind", "unsupported value %q", policy.TargetKind)
	}
	if err := validateUUID("target_id", policy.TargetID); err != nil {
		return err
	}
	if policy.PresetNames == nil || policy.Selectors == nil {
		return invalid("policy", "preset_names and selectors must be present as JSON arrays")
	}
	if err := validateUniqueNames("preset_names", policy.PresetNames); err != nil {
		return err
	}
	if err := validateSelectors(policy.Selectors); err != nil {
		return err
	}
	if err := validateHash("effective_hash", policy.EffectiveHash); err != nil {
		return err
	}
	if policy.Generation == 0 {
		return invalid("generation", "must be positive")
	}
	if len(policy.PresetNames) == 0 && len(policy.Selectors) != 0 {
		return invalid("selectors", "cleared policy cannot retain selectors")
	}
	return nil
}

func (transport Transport) Validate() error {
	if err := validateSchema("transport", transport.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if transport.OwnerKind != TargetNode && transport.OwnerKind != TargetClient {
		return invalid("owner_kind", "unsupported value %q", transport.OwnerKind)
	}
	if err := validateUUID("owner_id", transport.OwnerID); err != nil {
		return err
	}
	if transport.Kind != TransportStandard && transport.Kind != TransportRestricted {
		return invalid("kind", "unsupported value %q", transport.Kind)
	}
	if transport.State != TransportActive && transport.State != TransportStandby && transport.State != TransportDegraded && transport.State != TransportDisabled {
		return invalid("state", "unsupported value %q", transport.State)
	}
	if transport.CredentialGeneration == 0 {
		return invalid("credential_generation", "must be positive")
	}
	if err := validateOpaqueRef("credential_ref", transport.CredentialRef); err != nil {
		return err
	}
	if err := validateHash("config_hash", transport.ConfigHash); err != nil {
		return err
	}
	switch transport.Kind {
	case TransportStandard:
		if transport.Provider != "wireguard" || transport.Protocol != ProtocolUDP || transport.Port != 51820 || transport.HandshakeHost != "" || strings.TrimSpace(transport.PublicKey) == "" {
			return invalid("kind", "standard transport must use wireguard UDP/51820, a public key, and no handshake host")
		}
	case TransportRestricted:
		if transport.Provider != "mihomo" || transport.Protocol != ProtocolTCP || transport.Port != 8443 {
			return invalid("kind", "restricted transport must use mihomo TCP/8443")
		}
		if err := validateDomain("handshake_host", transport.HandshakeHost); err != nil {
			return err
		}
		if transport.PublicKey != "" {
			return invalid("public_key", "restricted transport must not expose a public key")
		}
	}
	return nil
}

func (expose Expose) Validate() error {
	if err := validateSchema("expose", expose.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateUUID("id", expose.ID); err != nil {
		return err
	}
	if err := validateUUID("node_id", expose.NodeID); err != nil {
		return err
	}
	if expose.Name != "" {
		if err := validateName("name", expose.Name); err != nil {
			return err
		}
	}
	if err := validateUpstream("upstream", expose.Upstream); err != nil {
		return err
	}
	if expose.RouteMode != RouteExact && expose.RouteMode != RoutePrefix {
		return invalid("route_mode", "unsupported value %q", expose.RouteMode)
	}
	if err := validateHTTPPath("path", expose.Path); err != nil {
		return err
	}
	if expose.BodyLimitBytes < 1 || expose.BodyLimitBytes > 8*1024*1024 {
		return invalid("body_limit_bytes", "must be between 1 and 8388608")
	}
	if expose.UpstreamTimeoutSeconds < 1 || expose.UpstreamTimeoutSeconds > 60 {
		return invalid("upstream_timeout_seconds", "must be between 1 and 60")
	}
	if expose.ConcurrentRequests < 1 || expose.ConcurrentRequests > 40 {
		return invalid("concurrent_requests", "must be between 1 and 40")
	}
	if expose.TunnelPort < 1024 || expose.TunnelPort > 65535 {
		return invalid("tunnel_port", "must be between 1024 and 65535")
	}
	if expose.State != ExposePending && expose.State != ExposeReady && expose.State != ExposeDegraded && expose.State != ExposeDisabled {
		return invalid("state", "unsupported value %q", expose.State)
	}
	if expose.Generation == 0 {
		return invalid("generation", "must be positive")
	}
	return validateTime("created_at", expose.CreatedAt)
}

func (certificate Certificate) Validate() error {
	if err := validateSchema("certificate", certificate.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateUUID("id", certificate.ID); err != nil {
		return err
	}
	switch certificate.Kind {
	case CertificatePublicIngress, CertificateControlCA, CertificateControlServer, CertificateControlNode, CertificateTunnelServer:
	default:
		return invalid("kind", "unsupported value %q", certificate.Kind)
	}
	if certificate.OwnerKind != "host" && certificate.OwnerKind != "node" {
		return invalid("owner_kind", "must be host or node")
	}
	if err := validateUUID("owner_id", certificate.OwnerID); err != nil {
		return err
	}
	if err := validateFingerprint("fingerprint", certificate.Fingerprint); err != nil {
		return err
	}
	if !serialPattern.MatchString(certificate.SerialHex) {
		return invalid("serial_hex", "must contain 1-32 lowercase hexadecimal digits")
	}
	if strings.TrimSpace(certificate.Subject) == "" || strings.ContainsAny(certificate.Subject, "\r\n") {
		return invalid("subject", "must be non-empty and single-line")
	}
	if len(certificate.SANs) == 0 {
		return invalid("sans", "must not be empty")
	}
	if err := validateUniqueStrings("sans", certificate.SANs); err != nil {
		return err
	}
	if err := validateTime("not_before", certificate.NotBefore); err != nil {
		return err
	}
	if err := validateTime("not_after", certificate.NotAfter); err != nil {
		return err
	}
	if !certificate.NotAfter.After(certificate.NotBefore) {
		return invalid("not_after", "must follow not_before")
	}
	if certificate.WarningDays < 1 || certificate.WarningDays > 365 {
		return invalid("warning_days", "must be between 1 and 365")
	}
	if certificate.Generation == 0 {
		return invalid("generation", "must be positive")
	}
	if err := validateOpaqueRef("certificate_ref", certificate.CertificateRef); err != nil {
		return err
	}
	if certificate.PrivateKeyRef != "" {
		if err := validateOpaqueRef("private_key_ref", certificate.PrivateKeyRef); err != nil {
			return err
		}
	}
	if certificate.Kind == CertificateControlNode && certificate.OwnerKind != "node" {
		return invalid("owner_kind", "control node certificate must be node-owned")
	}
	if certificate.Kind != CertificateControlNode && certificate.OwnerKind != "host" {
		return invalid("owner_kind", "non-node certificate must be host-owned")
	}
	return nil
}

func (operation Operation) Validate() error {
	if err := validateSchema("operation", operation.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateUUID("id", operation.ID); err != nil {
		return err
	}
	switch operation.Type {
	case OperationInit, OperationJoin, OperationApply, OperationRepair, OperationRotate, OperationRevoke, OperationDelete, OperationTransportSwitch, OperationExposeCreate, OperationExposeRemove, OperationCertificateRotate, OperationTrustRotate, OperationRestore, OperationUpdate, OperationUninstall, OperationPurge:
	default:
		return invalid("type", "unsupported value %q", operation.Type)
	}
	if !validOperationState(operation.State) {
		return invalid("state", "unsupported value %q", operation.State)
	}
	if (operation.TargetKind == "") != (operation.TargetID == "") {
		return invalid("target", "kind and id must be present together")
	}
	if operation.TargetID != "" {
		if !validOperationTarget(operation.TargetKind) {
			return invalid("target_kind", "unsupported value %q", operation.TargetKind)
		}
		if strings.TrimSpace(operation.TargetID) == "" || len(operation.TargetID) > 128 || strings.ContainsAny(operation.TargetID, "\r\n") {
			return invalid("target_id", "must be a non-empty, single-line resource reference of at most 128 bytes")
		}
	}
	if operation.RequestID != "" {
		if err := validateUUID("request_id", operation.RequestID); err != nil {
			return err
		}
	}
	if operation.DesiredGeneration < operation.ExpectedGeneration {
		return invalid("desired_generation", "must not precede expected_generation")
	}
	if err := validateTime("created_at", operation.CreatedAt); err != nil {
		return err
	}
	if err := validateTime("updated_at", operation.UpdatedAt); err != nil {
		return err
	}
	if operation.UpdatedAt.Before(operation.CreatedAt) {
		return invalid("updated_at", "must not precede created_at")
	}
	if operation.State == OperationFailed {
		if !errorCodePattern.MatchString(operation.ErrorCode) {
			return invalid("error_code", "failed operation requires a stable error code")
		}
	} else if operation.ErrorCode != "" {
		return invalid("error_code", "is allowed only for failed operations")
	}
	if operation.Steps == nil {
		return invalid("steps", "must be present as a JSON array")
	}
	stepNames := make(map[string]struct{}, len(operation.Steps))
	for index, step := range operation.Steps {
		if err := step.Validate(); err != nil {
			return wrap(indexPath("steps", index), err)
		}
		if _, duplicate := stepNames[step.Name]; duplicate {
			return invalid(indexPath("steps", index)+".name", "duplicates an operation step")
		}
		stepNames[step.Name] = struct{}{}
	}
	return nil
}

func (step OperationStep) Validate() error {
	if !componentPattern.MatchString(step.Name) {
		return invalid("name", "must be a stable lower-case identifier")
	}
	if !validOperationState(step.State) {
		return invalid("state", "unsupported value %q", step.State)
	}
	return validateTime("updated_at", step.UpdatedAt)
}

func (session LoggingSession) Validate() error {
	if err := validateSchema("logging", session.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateUUID("id", session.ID); err != nil {
		return err
	}
	switch session.Scope {
	case LogControl, LogTransport, LogRouting, LogDNS, LogTunnel, LogIngress, LogAll:
	default:
		return invalid("scope", "unsupported value %q", session.Scope)
	}
	switch session.Level {
	case LogError, LogInfo, LogDebug, LogTrace:
	default:
		return invalid("level", "unsupported value %q", session.Level)
	}
	if session.Destination != LogToJournald && session.Destination != LogToFile {
		return invalid("destination", "unsupported value %q", session.Destination)
	}
	if session.Destination == LogToFile {
		if !filepath.IsAbs(session.FilePath) {
			return invalid("file_path", "file destination requires an absolute path")
		}
	} else if session.FilePath != "" {
		return invalid("file_path", "is allowed only for file destination")
	}
	if session.State != LogActive && session.State != LogExpired && session.State != LogDisabled {
		return invalid("state", "unsupported value %q", session.State)
	}
	if err := validateTime("started_at", session.StartedAt); err != nil {
		return err
	}
	if err := validateTime("expires_at", session.ExpiresAt); err != nil {
		return err
	}
	duration := session.ExpiresAt.Sub(session.StartedAt)
	if duration <= 0 || duration > time.Hour {
		return invalid("expires_at", "must be after started_at and no more than one hour later")
	}
	return nil
}

func (backup Backup) Validate() error {
	if err := validateSchema("backup", backup.SchemaVersion, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateUUID("id", backup.ID); err != nil {
		return err
	}
	if backup.State != BackupComplete {
		return invalid("state", "unsupported value %q", backup.State)
	}
	if backup.Format != "vpnctl-backup-v1" {
		return invalid("format", "unsupported value %q", backup.Format)
	}
	if !filepath.IsAbs(backup.Path) {
		return invalid("path", "must be absolute")
	}
	if err := validateHash("sha256", backup.SHA256); err != nil {
		return err
	}
	if backup.SizeBytes <= 0 || backup.StateGeneration == 0 {
		return invalid("size_bytes", "size and source state generation must be positive")
	}
	if err := validateIPv4("public_ipv4", backup.PublicIPv4); err != nil {
		return err
	}
	return validateTime("created_at", backup.CreatedAt)
}

func (manifest ComponentManifest) Validate() error {
	if err := validateSchema("component manifest", manifest.SchemaVersion, ComponentManifestSchemaVersion); err != nil {
		return err
	}
	if manifest.ManifestVersion != 1 {
		return invalid("manifest_version", "unsupported value %d", manifest.ManifestVersion)
	}
	if strings.TrimSpace(manifest.VPNCTLVersion) == "" || strings.ContainsAny(manifest.VPNCTLVersion, " \t\r\n") {
		return invalid("vpnctl_version", "must be a non-empty token")
	}
	if len(manifest.ControlProtocols) == 0 {
		return invalid("control_protocols", "must not be empty")
	}
	if err := validateUniqueStrings("control_protocols", manifest.ControlProtocols); err != nil {
		return err
	}
	for index, protocol := range manifest.ControlProtocols {
		if !protocolPattern.MatchString(protocol) {
			return invalid(indexPath("control_protocols", index), "must be major.minor")
		}
	}
	if manifest.StateSchemaMinimum < 1 || manifest.StateSchemaMaximum < manifest.StateSchemaMinimum {
		return invalid("state_schema_minimum", "invalid supported state schema range")
	}
	if manifest.TargetOS != "ubuntu 24.04" || manifest.TargetArchitecture != "amd64" {
		return invalid("target", "must be ubuntu 24.04 amd64")
	}
	if manifest.HandshakeHostListVersion < 1 {
		return invalid("handshake_host_list_version", "must be positive")
	}
	if len(manifest.Components) == 0 {
		return invalid("components", "must not be empty")
	}
	seen := make(map[string]struct{}, len(manifest.Components))
	for index, component := range manifest.Components {
		if err := component.Validate(); err != nil {
			return wrap(indexPath("components", index), err)
		}
		if _, duplicate := seen[component.Name]; duplicate {
			return invalid(indexPath("components", index)+".name", "duplicates component %s", component.Name)
		}
		seen[component.Name] = struct{}{}
	}
	return nil
}

func (component ComponentPin) Validate() error {
	if !componentPattern.MatchString(component.Name) {
		return invalid("name", "must be a stable lower-case identifier")
	}
	if strings.TrimSpace(component.Version) == "" || strings.ContainsAny(component.Version, "\r\n") {
		return invalid("version", "must be non-empty and single-line")
	}
	if strings.TrimSpace(component.Source) == "" || strings.ContainsAny(component.Source, "\r\n") {
		return invalid("source", "must be non-empty and single-line")
	}
	if component.Bundled {
		if err := validateHash("sha256", component.SHA256); err != nil {
			return err
		}
	} else if component.SHA256 != "" {
		if err := validateHash("sha256", component.SHA256); err != nil {
			return err
		}
	}
	if len(component.Capabilities) == 0 {
		return invalid("capabilities", "must not be empty")
	}
	for index, capability := range component.Capabilities {
		if !componentPattern.MatchString(capability) {
			return invalid(indexPath("capabilities", index), "must be a stable lower-case identifier")
		}
	}
	return validateUniqueStrings("capabilities", component.Capabilities)
}

func validateResource(kind string, schema int, id, name string, lifecycle Lifecycle, overlayIPv4 string, credentialGeneration uint64, activeTransport TransportKind, createdAt time.Time, revokedAt *time.Time) error {
	if err := validateSchema(kind, schema, ResourceSchemaVersion); err != nil {
		return err
	}
	if err := validateUUID("id", id); err != nil {
		return err
	}
	if err := validateName("name", name); err != nil {
		return err
	}
	if lifecycle != LifecycleActive && lifecycle != LifecycleRevoked && lifecycle != LifecycleDeleted {
		return invalid("lifecycle", "unsupported value %q", lifecycle)
	}
	if err := validateIPv4("overlay_ipv4", overlayIPv4); err != nil {
		return err
	}
	if credentialGeneration == 0 {
		return invalid("credential_generation", "must be positive")
	}
	if activeTransport != TransportStandard && activeTransport != TransportRestricted {
		return invalid("active_transport", "unsupported value %q", activeTransport)
	}
	if err := validateTime("created_at", createdAt); err != nil {
		return err
	}
	if lifecycle == LifecycleActive {
		if revokedAt != nil {
			return invalid("revoked_at", "active resource cannot have revocation time")
		}
	} else {
		if revokedAt == nil {
			return invalid("revoked_at", "revoked or deleted resource requires revocation time")
		}
		if err := validateTime("revoked_at", *revokedAt); err != nil {
			return err
		}
		if revokedAt.Before(createdAt) {
			return invalid("revoked_at", "must not precede created_at")
		}
	}
	return nil
}

func validateActiveTransport(kind TargetKind, id string, active TransportKind, lifecycle Lifecycle, states map[string]map[TransportKind]TransportState) error {
	owner := targetKey(kind, id)
	ownerStates := states[owner]
	if len(ownerStates) == 0 {
		if lifecycle == LifecycleActive {
			return invalid("transports", "active %s %s has no transport records", kind, id)
		}
		return nil
	}
	if lifecycle == LifecycleDeleted {
		return invalid("transports", "deleted %s %s retains transports", kind, id)
	}
	if lifecycle == LifecycleRevoked {
		for _, state := range ownerStates {
			if state != TransportDisabled {
				return invalid("transports", "revoked %s %s retains an enabled transport", kind, id)
			}
		}
		return nil
	}
	activeState, found := ownerStates[active]
	if !found || (activeState != TransportActive && activeState != TransportDegraded) {
		return invalid("transports", "%s %s active transport does not match its transport records", kind, id)
	}
	for transportKind, state := range ownerStates {
		if transportKind != active && state != TransportStandby {
			return invalid("transports", "%s %s has a non-standby inactive transport", kind, id)
		}
	}
	return nil
}

func validateSelectors(selectors []Selector) error {
	seen := make(map[string]struct{}, len(selectors))
	for index, selector := range selectors {
		path := indexPath("selectors", index)
		switch selector.Kind {
		case SelectorDomain, SelectorDomainSuffix:
			if err := validateDomain(path+".value", selector.Value); err != nil {
				return err
			}
		case SelectorIPCIDR:
			prefix, err := netip.ParsePrefix(selector.Value)
			if err != nil || prefix.String() != selector.Value {
				return invalid(path+".value", "must be a canonical IP prefix")
			}
		default:
			return invalid(path+".kind", "unsupported value %q", selector.Kind)
		}
		key := string(selector.Kind) + ":" + selector.Value + fmt.Sprintf(":%t", selector.Exclude)
		if _, duplicate := seen[key]; duplicate {
			return invalid(path, "duplicates a selector")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateSchema(kind string, got, want int) error {
	if got != want {
		return invalid("schema_version", "%s schema %d is unsupported; want %d", kind, got, want)
	}
	return nil
}

func validateUUID(path, value string) error {
	if !uuidPattern.MatchString(value) {
		return invalid(path, "must be a canonical lower-case UUID")
	}
	return nil
}

func validateName(path, value string) error {
	if !namePattern.MatchString(value) {
		return invalid(path, "must match %s", namePattern)
	}
	return nil
}

func validateUniqueNames(path string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if err := validateName(indexPath(path, index), value); err != nil {
			return err
		}
		key := strings.ToLower(value)
		if _, duplicate := seen[key]; duplicate {
			return invalid(indexPath(path, index), "duplicates a name")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateUniqueStrings(path string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
			return invalid(indexPath(path, index), "must be non-empty and single-line")
		}
		if _, duplicate := seen[value]; duplicate {
			return invalid(indexPath(path, index), "duplicates a value")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateHash(path, value string) error {
	if !hashPattern.MatchString(value) {
		return invalid(path, "must be a lower-case SHA-256 hexadecimal value")
	}
	return nil
}

func validateFingerprint(path, value string) error {
	if !fingerprintPattern.MatchString(value) {
		return invalid(path, "must use sha256:<lower-case-hex>")
	}
	return nil
}

func validateOpaqueRef(path, value string) error {
	if !secretRefPattern.MatchString(value) {
		return invalid(path, "must be an opaque typed reference")
	}
	return nil
}

func validateIPv4(path, value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value {
		return invalid(path, "must be a canonical IPv4 address")
	}
	return nil
}

func validateIPv4Prefix(path, value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != value {
		return netip.Prefix{}, invalid(path, "must be a canonical IPv4 prefix")
	}
	return prefix, nil
}

func validateDomain(path, value string) error {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return invalid(path, "must be a canonical lower-case DNS name")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid(path, "contains an invalid DNS label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return invalid(path, "contains an invalid DNS character")
			}
		}
	}
	return nil
}

func validateUpstream(path, value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return invalid(path, "must be normalized host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return invalid(path, "contains an invalid port")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.String() != host {
			return invalid(path, "contains a non-canonical IP address")
		}
	} else if host != "localhost" {
		if err := validateDomain(path, host); err != nil {
			return err
		}
	}
	return nil
}

func validateHTTPPath(path, value string) error {
	if value == "" || value[0] != '/' || len(value) > 512 || strings.ContainsAny(value, "?#\r\n\x00") || strings.Contains(value, "//") {
		return invalid(path, "must be an absolute normalized HTTP path without query or fragment")
	}
	return nil
}

func validateTime(path string, value time.Time) error {
	if value.IsZero() {
		return invalid(path, "must not be zero")
	}
	_, offset := value.Zone()
	if offset != 0 {
		return invalid(path, "must use UTC")
	}
	return nil
}

func validOperationState(state OperationState) bool {
	return state == OperationPending || state == OperationStaging || state == OperationActive || state == OperationDegraded || state == OperationFailed || state == OperationCompleted
}

func validOperationTarget(kind string) bool {
	return kind == "host" || kind == "node" || kind == "client" || kind == "preset" || kind == "policy" || kind == "transport" || kind == "expose" || kind == "certificate" || kind == "backup"
}

func targetExists(kind TargetKind, id string, nodes map[string]Node, clients map[string]Client) bool {
	if kind == TargetNode {
		_, found := nodes[id]
		return found
	}
	if kind == TargetClient {
		_, found := clients[id]
		return found
	}
	return false
}

func targetKey(kind TargetKind, id string) string {
	return string(kind) + ":" + id
}

func equalStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func indexPath(path string, index int) string {
	return fmt.Sprintf("%s[%d]", path, index)
}

func invalid(path, format string, arguments ...any) error {
	return fmt.Errorf("%s: %s", path, fmt.Sprintf(format, arguments...))
}

func wrap(path string, err error) error {
	return fmt.Errorf("%s: %w", path, err)
}
