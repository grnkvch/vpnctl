package model

import "time"

const (
	StateSchemaVersion             = 1
	ResourceSchemaVersion          = 1
	ComponentManifestSchemaVersion = 1
	InviteTTL                      = 15 * time.Minute
)

type Role string

const (
	RoleGateway Role = "gateway"
	RoleNode    Role = "node"
)

type Lifecycle string

const (
	LifecycleActive  Lifecycle = "active"
	LifecycleRevoked Lifecycle = "revoked"
	LifecycleDeleted Lifecycle = "deleted"
)

type TargetKind string

const (
	TargetNode   TargetKind = "node"
	TargetClient TargetKind = "client"
)

type TransportKind string

const (
	TransportStandard   TransportKind = "standard"
	TransportRestricted TransportKind = "restricted"
)

type TransportState string

const (
	TransportActive   TransportState = "active"
	TransportStandby  TransportState = "standby"
	TransportDegraded TransportState = "degraded"
	TransportDisabled TransportState = "disabled"
)

type NetworkProtocol string

const (
	ProtocolTCP NetworkProtocol = "tcp"
	ProtocolUDP NetworkProtocol = "udp"
)

type SelectorKind string

const (
	SelectorDomain       SelectorKind = "domain"
	SelectorDomainSuffix SelectorKind = "domain-suffix"
	SelectorIPCIDR       SelectorKind = "ip-cidr"
)

type RouteMode string

const (
	RouteExact  RouteMode = "exact"
	RoutePrefix RouteMode = "prefix"
)

type ExposeState string

const (
	ExposePending  ExposeState = "pending"
	ExposeReady    ExposeState = "ready"
	ExposeDegraded ExposeState = "degraded"
	ExposeDisabled ExposeState = "disabled"
)

type CertificateKind string

const (
	CertificatePublicIngress CertificateKind = "public-ingress"
	CertificateControlCA     CertificateKind = "control-ca"
	CertificateControlServer CertificateKind = "control-server"
	CertificateControlNode   CertificateKind = "control-node"
	CertificateTunnelServer  CertificateKind = "tunnel-server"
)

type OperationType string

const (
	OperationInit              OperationType = "init"
	OperationJoin              OperationType = "join"
	OperationApply             OperationType = "apply"
	OperationRepair            OperationType = "repair"
	OperationRotate            OperationType = "rotate"
	OperationRevoke            OperationType = "revoke"
	OperationDelete            OperationType = "delete"
	OperationTransportSwitch   OperationType = "transport-switch"
	OperationHandshakeHost     OperationType = "handshake-host-replace"
	OperationExposeCreate      OperationType = "expose-create"
	OperationExposeRemove      OperationType = "expose-remove"
	OperationCertificateRotate OperationType = "certificate-rotate"
	OperationTrustRotate       OperationType = "trust-rotate"
	OperationRestore           OperationType = "restore"
	OperationUpdate            OperationType = "update"
	OperationUninstall         OperationType = "uninstall"
	OperationPurge             OperationType = "purge"
)

type OperationState string

const (
	OperationPending   OperationState = "pending"
	OperationStaging   OperationState = "staging"
	OperationActive    OperationState = "active"
	OperationDegraded  OperationState = "degraded"
	OperationFailed    OperationState = "failed"
	OperationCompleted OperationState = "completed"
)

type ResultStatus string

const (
	ResultOK       ResultStatus = "ok"
	ResultPending  ResultStatus = "pending"
	ResultDegraded ResultStatus = "degraded"
	ResultFailed   ResultStatus = "failed"
)

type LogScope string

const (
	LogControl   LogScope = "control"
	LogTransport LogScope = "transport"
	LogRouting   LogScope = "routing"
	LogDNS       LogScope = "dns"
	LogTunnel    LogScope = "tunnel"
	LogIngress   LogScope = "ingress"
	LogAll       LogScope = "all"
)

type LogLevel string

const (
	LogError LogLevel = "error"
	LogInfo  LogLevel = "info"
	LogDebug LogLevel = "debug"
	LogTrace LogLevel = "trace"
)

type LogDestination string

const (
	LogToJournald LogDestination = "journald"
	LogToFile     LogDestination = "file"
)

type LogState string

const (
	LogActive   LogState = "active"
	LogExpired  LogState = "expired"
	LogDisabled LogState = "disabled"
)

type BackupState string

const (
	BackupComplete BackupState = "complete"
)

type InviteState string

const (
	InviteActive    InviteState = "active"
	InviteCancelled InviteState = "cancelled"
	InviteConsumed  InviteState = "consumed"
)

type SecretRef string

type State struct {
	SchemaVersion       int                  `json:"schema_version"`
	Generation          uint64               `json:"generation"`
	Host                Host                 `json:"host"`
	HandshakeHost       *HandshakeHost       `json:"handshake_host,omitempty"`
	HandshakeHostChange *HandshakeHostChange `json:"handshake_host_change,omitempty"`
	EnrollmentIdentity  *EnrollmentIdentity  `json:"enrollment_signing_identity,omitempty"`
	Invites             []Invite             `json:"invites"`
	Nodes               []Node               `json:"nodes"`
	Clients             []Client             `json:"clients"`
	Presets             []Preset             `json:"presets"`
	Policies            []Policy             `json:"policies"`
	Transports          []Transport          `json:"transports"`
	Exposes             []Expose             `json:"exposes"`
	Certificates        []Certificate        `json:"certificates"`
	Operations          []Operation          `json:"operations"`
	Logging             []LoggingSession     `json:"logging"`
	Backups             []Backup             `json:"backups"`
	Components          ComponentManifest    `json:"components"`
}

// Invite is the gateway-authoritative, non-secret half of a one-time node
// enrollment token. SecretHash is a one-way digest; plaintext token material
// is never persisted in State.
type Invite struct {
	SchemaVersion         int         `json:"schema_version"`
	ID                    string      `json:"id"`
	NodeName              string      `json:"node_name"`
	ControlProtocol       string      `json:"control_protocol"`
	GatewayEndpoint       string      `json:"gateway_endpoint"`
	EnrollmentFingerprint string      `json:"enrollment_fingerprint"`
	SecretHash            string      `json:"secret_hash"`
	State                 InviteState `json:"state"`
	IssuedAt              time.Time   `json:"issued_at"`
	ExpiresAt             time.Time   `json:"expires_at"`
	CancelledAt           *time.Time  `json:"cancelled_at,omitempty"`
	ConsumedAt            *time.Time  `json:"consumed_at,omitempty"`
	ConsumptionHash       string      `json:"consumption_hash,omitempty"`
}

// HandshakeHost is the single restricted-transport TLS disguise selected from
// a signed release list. CandidateID is stable across hostname-list revisions;
// renderers use Hostname, while lifecycle operations use both values to avoid
// silently adopting a different candidate.
type HandshakeHost struct {
	SchemaVersion int       `json:"schema_version"`
	ListVersion   int       `json:"list_version"`
	CandidateID   string    `json:"candidate_id"`
	Hostname      string    `json:"hostname"`
	SelectedAt    time.Time `json:"selected_at"`
}

type HandshakeHostChangeState string

const (
	HandshakeHostPrepared  HandshakeHostChangeState = "prepared"
	HandshakeHostCommitted HandshakeHostChangeState = "committed"
)

// HandshakeHostChange is the single durable gateway-only staged replacement.
// Previous is a bounded rollback snapshot; affected IDs are non-secret impact
// metadata used to report node-config and Clash-export staleness after commit.
type HandshakeHostChange struct {
	SchemaVersion     int                      `json:"schema_version"`
	OperationID       string                   `json:"operation_id"`
	State             HandshakeHostChangeState `json:"state"`
	Previous          HandshakeHost            `json:"previous"`
	Candidate         HandshakeHost            `json:"candidate"`
	AffectedNodeIDs   []string                 `json:"affected_node_ids"`
	AffectedClientIDs []string                 `json:"affected_client_ids"`
	PreparedAt        time.Time                `json:"prepared_at"`
	CommittedAt       *time.Time               `json:"committed_at,omitempty"`
	RollbackExpiresAt *time.Time               `json:"rollback_expires_at,omitempty"`
}

type Host struct {
	SchemaVersion     int          `json:"schema_version"`
	ID                string       `json:"id"`
	Role              Role         `json:"role"`
	OS                string       `json:"os"`
	OSVersion         string       `json:"os_version"`
	Architecture      string       `json:"architecture"`
	InitializedAt     time.Time    `json:"initialized_at"`
	PublicIPv4        string       `json:"public_ipv4,omitempty"`
	ExternalInterface string       `json:"external_interface,omitempty"`
	SSHPort           int          `json:"ssh_port,omitempty"`
	ClientCIDR        string       `json:"client_cidr,omitempty"`
	NodeCIDR          string       `json:"node_cidr,omitempty"`
	ManagedSwap       *ManagedSwap `json:"managed_swap,omitempty"`
}

type ManagedSwap struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	Enabled   bool   `json:"enabled"`
}

type Node struct {
	SchemaVersion        int                 `json:"schema_version"`
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	Lifecycle            Lifecycle           `json:"lifecycle"`
	OverlayIPv4          string              `json:"overlay_ipv4"`
	CredentialGeneration uint64              `json:"credential_generation"`
	AssignedPresets      []string            `json:"assigned_presets"`
	ActiveTransport      TransportKind       `json:"active_transport"`
	IdempotencyRecords   []IdempotencyRecord `json:"idempotency_records"`
	Gateway              *GatewayTrust       `json:"gateway,omitempty"`
	CreatedAt            time.Time           `json:"created_at"`
	RevokedAt            *time.Time          `json:"revoked_at,omitempty"`
}

type IdempotencyRecord struct {
	RequestID       string        `json:"request_id"`
	Operation       OperationType `json:"operation_type"`
	ResultStatus    ResultStatus  `json:"result_status"`
	ResultHash      string        `json:"result_hash"`
	StateGeneration uint64        `json:"state_generation"`
	RecordedAt      time.Time     `json:"recorded_at"`
}

type GatewayTrust struct {
	PublicIPv4                    string    `json:"public_ipv4"`
	NodeCIDR                      string    `json:"node_cidr"`
	GatewayOverlayIPv4            string    `json:"gateway_overlay_ipv4"`
	ControlProtocol               string    `json:"control_protocol"`
	EnrollmentFingerprint         string    `json:"enrollment_fingerprint"`
	EnrollmentPublicKeyRef        string    `json:"enrollment_public_key_ref"`
	ControlCAFingerprints         []string  `json:"control_ca_fingerprints"`
	ControlCACertificateRefs      []string  `json:"control_ca_certificate_refs"`
	StandardPublicKey             string    `json:"standard_public_key"`
	RestrictedServerCredentialRef SecretRef `json:"restricted_server_credential_ref"`
	LastKnownGatewayGeneration    uint64    `json:"last_known_gateway_generation"`
	PendingRequestID              string    `json:"pending_request_id,omitempty"`
}

type Client struct {
	SchemaVersion        int           `json:"schema_version"`
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	Platform             string        `json:"platform"`
	Lifecycle            Lifecycle     `json:"lifecycle"`
	OverlayIPv4          string        `json:"overlay_ipv4"`
	CredentialGeneration uint64        `json:"credential_generation"`
	AssignedPresets      []string      `json:"assigned_presets"`
	ActiveTransport      TransportKind `json:"active_transport"`
	CreatedAt            time.Time     `json:"created_at"`
	RevokedAt            *time.Time    `json:"revoked_at,omitempty"`
}

type Preset struct {
	SchemaVersion int        `json:"schema_version"`
	Name          string     `json:"name"`
	SourceHash    string     `json:"source_hash"`
	EffectiveHash string     `json:"effective_hash"`
	Selectors     []Selector `json:"selectors"`
	Generation    uint64     `json:"generation"`
	AppliedAt     time.Time  `json:"applied_at"`
}

type Selector struct {
	Kind    SelectorKind `json:"kind"`
	Value   string       `json:"value"`
	Exclude bool         `json:"exclude"`
}

type Policy struct {
	SchemaVersion int        `json:"schema_version"`
	TargetKind    TargetKind `json:"target_kind"`
	TargetID      string     `json:"target_id"`
	PresetNames   []string   `json:"preset_names"`
	Selectors     []Selector `json:"selectors"`
	EffectiveHash string     `json:"effective_hash"`
	Generation    uint64     `json:"generation"`
}

type Transport struct {
	SchemaVersion        int             `json:"schema_version"`
	OwnerKind            TargetKind      `json:"owner_kind"`
	OwnerID              string          `json:"owner_id"`
	Kind                 TransportKind   `json:"kind"`
	State                TransportState  `json:"state"`
	Provider             string          `json:"provider"`
	Protocol             NetworkProtocol `json:"protocol"`
	Port                 int             `json:"port"`
	CredentialGeneration uint64          `json:"credential_generation"`
	CredentialRef        SecretRef       `json:"credential_ref"`
	PublicKey            string          `json:"public_key,omitempty"`
	HandshakeHost        string          `json:"handshake_host,omitempty"`
	ConfigHash           string          `json:"config_hash"`
}

type Expose struct {
	SchemaVersion          int         `json:"schema_version"`
	ID                     string      `json:"id"`
	NodeID                 string      `json:"node_id"`
	Name                   string      `json:"name,omitempty"`
	Upstream               string      `json:"upstream"`
	RouteMode              RouteMode   `json:"route_mode"`
	Path                   string      `json:"path"`
	BodyLimitBytes         int64       `json:"body_limit_bytes"`
	UpstreamTimeoutSeconds int         `json:"upstream_timeout_seconds"`
	ConcurrentRequests     int         `json:"concurrent_requests"`
	TunnelPort             int         `json:"tunnel_port"`
	State                  ExposeState `json:"state"`
	Generation             uint64      `json:"generation"`
	CreatedAt              time.Time   `json:"created_at"`
}

type Certificate struct {
	SchemaVersion        int             `json:"schema_version"`
	ID                   string          `json:"id"`
	Kind                 CertificateKind `json:"kind"`
	OwnerKind            string          `json:"owner_kind"`
	OwnerID              string          `json:"owner_id"`
	Fingerprint          string          `json:"fingerprint"`
	SerialHex            string          `json:"serial_hex"`
	Subject              string          `json:"subject"`
	SANs                 []string        `json:"sans"`
	NotBefore            time.Time       `json:"not_before"`
	NotAfter             time.Time       `json:"not_after"`
	WarningDays          int             `json:"warning_days"`
	Generation           uint64          `json:"generation"`
	CredentialGeneration uint64          `json:"credential_generation,omitempty"`
	CertificateRef       string          `json:"certificate_ref"`
	PrivateKeyRef        SecretRef       `json:"private_key_ref,omitempty"`
}

func (certificate Certificate) EffectiveCredentialGeneration() uint64 {
	if certificate.CredentialGeneration != 0 {
		return certificate.CredentialGeneration
	}
	return certificate.Generation
}

type EnrollmentIdentity struct {
	SchemaVersion int       `json:"schema_version"`
	Algorithm     string    `json:"algorithm"`
	Fingerprint   string    `json:"fingerprint"`
	PublicKeyRef  string    `json:"public_key_ref"`
	PrivateKeyRef SecretRef `json:"private_key_ref"`
	Generation    uint64    `json:"generation"`
	CreatedAt     time.Time `json:"created_at"`
}

type Operation struct {
	SchemaVersion      int             `json:"schema_version"`
	ID                 string          `json:"id"`
	Type               OperationType   `json:"type"`
	State              OperationState  `json:"state"`
	TargetKind         string          `json:"target_kind,omitempty"`
	TargetID           string          `json:"target_id,omitempty"`
	RequestID          string          `json:"request_id,omitempty"`
	ExpectedGeneration uint64          `json:"expected_generation"`
	DesiredGeneration  uint64          `json:"desired_generation"`
	Steps              []OperationStep `json:"steps"`
	ErrorCode          string          `json:"error_code,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type OperationStep struct {
	Name      string         `json:"name"`
	State     OperationState `json:"state"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type LoggingSession struct {
	SchemaVersion int            `json:"schema_version"`
	ID            string         `json:"id"`
	Scope         LogScope       `json:"scope"`
	Level         LogLevel       `json:"level"`
	Destination   LogDestination `json:"destination"`
	FilePath      string         `json:"file_path,omitempty"`
	State         LogState       `json:"state"`
	StartedAt     time.Time      `json:"started_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
}

type Backup struct {
	SchemaVersion   int         `json:"schema_version"`
	ID              string      `json:"id"`
	State           BackupState `json:"state"`
	Format          string      `json:"format"`
	Path            string      `json:"path"`
	SHA256          string      `json:"sha256"`
	SizeBytes       int64       `json:"size_bytes"`
	StateGeneration uint64      `json:"state_generation"`
	PublicIPv4      string      `json:"public_ipv4"`
	CreatedAt       time.Time   `json:"created_at"`
}

type ComponentManifest struct {
	SchemaVersion            int            `json:"schema_version"`
	ManifestVersion          int            `json:"manifest_version"`
	VPNCTLVersion            string         `json:"vpnctl_version"`
	ControlProtocols         []string       `json:"control_protocols"`
	StateSchemaMinimum       int            `json:"state_schema_minimum"`
	StateSchemaMaximum       int            `json:"state_schema_maximum"`
	TargetOS                 string         `json:"target_os"`
	TargetArchitecture       string         `json:"target_architecture"`
	HandshakeHostListVersion int            `json:"handshake_host_list_version"`
	MigrationReversible      bool           `json:"migration_reversible"`
	Components               []ComponentPin `json:"components"`
}

type ComponentPin struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Source       string   `json:"source"`
	Bundled      bool     `json:"bundled"`
	SHA256       string   `json:"sha256,omitempty"`
	Capabilities []string `json:"capabilities"`
}
