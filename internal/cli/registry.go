package cli

import (
	"errors"
	"fmt"
	"sort"
)

type HostRole string

const (
	RoleUninitialized HostRole = "uninitialized"
	RoleGateway       HostRole = "gateway"
	RoleNode          HostRole = "node"
)

type ConsentClass string

const (
	ConsentNone                       ConsentClass = "none"
	ConsentConfirm                    ConsentClass = "confirm"
	ConsentConditional                ConsentClass = "conditional"
	ConsentConfirmTypedIfIrreversible ConsentClass = "confirm+typed-if-irreversible"
	ConsentTyped                      ConsentClass = "typed"
)

type DeferSupport string

const (
	DeferNo       DeferSupport = "no"
	DeferYes      DeferSupport = "yes"
	DeferNodeOnly DeferSupport = "node only"
)

type CommandSpec struct {
	ID             string
	Syntax         string
	ResultContract string
	Roles          []HostRole
	Consent        ConsentClass
	SecretFlow     PromptKind
	DryRun         bool
	Defer          DeferSupport
}

var (
	ErrUnknownCommand  = errors.New("unknown v2 command")
	ErrUnsupportedRole = errors.New("command is unavailable for host role")
)

type RoleError struct {
	CommandID string
	Role      HostRole
	Allowed   []HostRole
}

func (err *RoleError) Error() string {
	return fmt.Sprintf("%s: command %s does not support role %s (allowed: %v)", ErrUnsupportedRole, err.CommandID, err.Role, err.Allowed)
}

func (err *RoleError) Unwrap() error { return ErrUnsupportedRole }

type CommandRegistry struct {
	commands map[string]CommandSpec
	ordered  []CommandSpec
}

type CommandHandler func(CommandSpec) error

func V2CommandRegistry() CommandRegistry {
	registry, err := NewCommandRegistry(v2CommandSpecs())
	if err != nil {
		panic(err)
	}
	return registry
}

func NewCommandRegistry(specs []CommandSpec) (CommandRegistry, error) {
	if len(specs) == 0 {
		return CommandRegistry{}, fmt.Errorf("command registry must not be empty")
	}
	registry := CommandRegistry{
		commands: make(map[string]CommandSpec, len(specs)),
		ordered:  make([]CommandSpec, 0, len(specs)),
	}
	contractRows := make(map[string]string, len(specs))
	for index, spec := range specs {
		canonical, err := validateCommandSpec(spec)
		if err != nil {
			return CommandRegistry{}, fmt.Errorf("command spec %d: %w", index, err)
		}
		if _, duplicate := registry.commands[canonical.ID]; duplicate {
			return CommandRegistry{}, fmt.Errorf("duplicate command ID %q", canonical.ID)
		}
		contractKey := canonical.Syntax + "\x00" + rolesLabel(canonical.Roles)
		if prior, duplicate := contractRows[contractKey]; duplicate {
			return CommandRegistry{}, fmt.Errorf("command %q duplicates contract row owned by %s", canonical.ID, prior)
		}
		contractRows[contractKey] = canonical.ID
		registry.commands[canonical.ID] = canonical
		registry.ordered = append(registry.ordered, canonical)
	}
	sort.Slice(registry.ordered, func(i, j int) bool { return registry.ordered[i].ID < registry.ordered[j].ID })
	return registry, nil
}

func (registry CommandRegistry) Commands() []CommandSpec {
	result := make([]CommandSpec, len(registry.ordered))
	for index, spec := range registry.ordered {
		result[index] = cloneCommandSpec(spec)
	}
	return result
}

func (registry CommandRegistry) Lookup(commandID string) (CommandSpec, bool) {
	spec, found := registry.commands[commandID]
	return cloneCommandSpec(spec), found
}

// Dispatch is the mandatory role gate in front of command handlers. Role
// rejection happens before handler invocation, so handlers cannot read-write
// state, touch the host, or contact a controller for an unsupported role.
func (registry CommandRegistry) Dispatch(commandID string, role HostRole, handler CommandHandler) error {
	spec, found := registry.commands[commandID]
	if !found {
		return fmt.Errorf("%w: %s", ErrUnknownCommand, commandID)
	}
	if !validHostRole(role) {
		return fmt.Errorf("invalid host role %q", role)
	}
	if !spec.AllowsRole(role) {
		return &RoleError{CommandID: commandID, Role: role, Allowed: append([]HostRole(nil), spec.Roles...)}
	}
	if handler == nil {
		return fmt.Errorf("command handler must not be nil")
	}
	return handler(cloneCommandSpec(spec))
}

func (spec CommandSpec) AllowsRole(role HostRole) bool {
	for _, allowed := range spec.Roles {
		if allowed == role {
			return true
		}
	}
	return false
}

func validateCommandSpec(spec CommandSpec) (CommandSpec, error) {
	spec = cloneCommandSpec(spec)
	if spec.ID == "" || spec.Syntax == "" || spec.ResultContract == "" {
		return CommandSpec{}, fmt.Errorf("id, syntax, and result contract are required")
	}
	if len(spec.Roles) == 0 {
		return CommandSpec{}, fmt.Errorf("command %s must allow at least one role", spec.ID)
	}
	seenRoles := make(map[HostRole]struct{}, len(spec.Roles))
	for _, role := range spec.Roles {
		if !validHostRole(role) {
			return CommandSpec{}, fmt.Errorf("command %s has invalid role %q", spec.ID, role)
		}
		if _, duplicate := seenRoles[role]; duplicate {
			return CommandSpec{}, fmt.Errorf("command %s duplicates role %s", spec.ID, role)
		}
		seenRoles[role] = struct{}{}
	}
	sort.Slice(spec.Roles, func(i, j int) bool { return roleOrder(spec.Roles[i]) < roleOrder(spec.Roles[j]) })
	switch spec.Consent {
	case ConsentNone, ConsentConfirm, ConsentConditional, ConsentConfirmTypedIfIrreversible, ConsentTyped:
	default:
		return CommandSpec{}, fmt.Errorf("command %s has invalid consent %q", spec.ID, spec.Consent)
	}
	switch spec.SecretFlow {
	case PromptNone, PromptSecretOnce, PromptSecretTwice, PromptSecretOutputOnce:
	default:
		return CommandSpec{}, fmt.Errorf("command %s has invalid secret flow %q", spec.ID, spec.SecretFlow)
	}
	switch spec.Defer {
	case DeferNo, DeferYes, DeferNodeOnly:
	default:
		return CommandSpec{}, fmt.Errorf("command %s has invalid defer support %q", spec.ID, spec.Defer)
	}
	if spec.Defer == DeferNodeOnly && !spec.AllowsRole(RoleNode) {
		return CommandSpec{}, fmt.Errorf("command %s has node-only defer without node role", spec.ID)
	}
	return cloneCommandSpec(spec), nil
}

func cloneCommandSpec(spec CommandSpec) CommandSpec {
	spec.Roles = append([]HostRole(nil), spec.Roles...)
	return spec
}

func validHostRole(role HostRole) bool {
	return role == RoleUninitialized || role == RoleGateway || role == RoleNode
}

func roleOrder(role HostRole) int {
	switch role {
	case RoleUninitialized:
		return 0
	case RoleGateway:
		return 1
	case RoleNode:
		return 2
	default:
		return 3
	}
}

func rolesLabel(roles []HostRole) string {
	if len(roles) == 3 {
		return "all"
	}
	if len(roles) == 2 && roles[0] == RoleGateway && roles[1] == RoleNode {
		return "gateway/node"
	}
	if len(roles) == 1 {
		return string(roles[0])
	}
	return fmt.Sprint(roles)
}

func v2CommandSpecs() []CommandSpec {
	all := []HostRole{RoleUninitialized, RoleGateway, RoleNode}
	initialized := []HostRole{RoleGateway, RoleNode}
	gateway := []HostRole{RoleGateway}
	node := []HostRole{RoleNode}
	specs := []CommandSpec{
		command("help", "help [command...]", "plain-text", all, ConsentNone, false, DeferNo),
		command("version", "version", "plain-text", all, ConsentNone, false, DeferNo),
		command("init.gateway", "init --gateway", "operation-v1:init.gateway", all, ConsentConfirm, true, DeferNo),
		command("init.node", "init --node", "operation-v1:init.node", all, ConsentConfirm, true, DeferNo),
		command("confirm", "confirm <transaction-id>", "operation-v1:confirm", gateway, ConsentNone, false, DeferNo),
		command("status", "status", "status-v1:status", initialized, ConsentNone, false, DeferNo),
		command("doctor", "doctor [scope]", "diagnostic-v1:doctor", initialized, ConsentNone, false, DeferNo),
		command("validate", "validate", "validation-v1:validate", initialized, ConsentNone, false, DeferNo),
		command("plan", "plan", "plan-v1:plan", initialized, ConsentNone, false, DeferNo),
		command("apply", "apply", "operation-v1:apply", initialized, ConsentConditional, false, DeferNo),
		command("repair", "repair", "operation-v1:repair", initialized, ConsentConfirm, true, DeferNo),
		command("invite", "invite <node-name>", "secret-issue-v1:invite", gateway, ConsentNone, true, DeferNo),
		command("invite.cancel", "invite cancel <invite-id>", "operation-v1:invite.cancel", gateway, ConsentNone, true, DeferNo),
		command("join", "join <transport> [preset...]", "operation-v1:join", node, ConsentConfirm, true, DeferNo),
		command("node.list", "node list", "collection-v1:node.list", gateway, ConsentNone, false, DeferNo),
		command("node.show", "node show <name-or-id>", "resource-v1:node.show", gateway, ConsentNone, false, DeferNo),
		command("node.revoke", "node revoke <name-or-id>", "operation-v1:node.revoke", gateway, ConsentConfirm, true, DeferNo),
		command("node.delete", "node delete <name-or-id>", "operation-v1:node.delete", gateway, ConsentConfirm, true, DeferNo),
		command("node.rotate", "node rotate", "operation-v1:node.rotate", node, ConsentConfirm, true, DeferNo),
		command("node.recover.gateway", "node recover <name-or-id>", "secret-issue-v1:node.recover", gateway, ConsentConfirm, true, DeferNo),
		command("node.recover.node", "node recover", "operation-v1:node.recover", node, ConsentConfirm, true, DeferNo),
		command("client.add", "client add <name> [preset...]", "operation-v1:client.add", gateway, ConsentNone, true, DeferNo),
		command("client.list", "client list", "collection-v1:client.list", gateway, ConsentNone, false, DeferNo),
		command("client.show", "client show <name-or-id>", "resource-v1:client.show", gateway, ConsentNone, false, DeferNo),
		command("client.revoke", "client revoke <name-or-id>", "operation-v1:client.revoke", gateway, ConsentConfirm, true, DeferNo),
		command("client.delete", "client delete <name-or-id>", "operation-v1:client.delete", gateway, ConsentConfirm, true, DeferNo),
		command("client.rotate", "client rotate <name-or-id>", "operation-v1:client.rotate", gateway, ConsentConfirm, true, DeferNo),
		command("client.export", "client export <name-or-id> <format>", "export-v1:client.export", gateway, ConsentNone, true, DeferNo),
		command("preset.list", "preset list", "collection-v1:preset.list", gateway, ConsentNone, false, DeferNo),
		command("preset.show", "preset show <name>", "resource-v1:preset.show", gateway, ConsentNone, false, DeferNo),
		command("preset.validate", "preset validate", "validation-v1:preset.validate", gateway, ConsentNone, false, DeferNo),
		command("preset.diff", "preset diff", "plan-v1:preset.diff", gateway, ConsentNone, false, DeferNo),
		command("preset.update", "preset update <name>", "operation-v1:preset.update", gateway, ConsentNone, true, DeferYes),
		command("policy.show.node", "policy show", "resource-v1:policy.show", node, ConsentNone, false, DeferNo),
		command("policy.show.gateway", "policy show --client <name-or-id>", "resource-v1:policy.show", gateway, ConsentNone, false, DeferNo),
		command("policy.set.node", "policy set <preset...>", "operation-v1:policy.set", node, ConsentNone, true, DeferYes),
		command("policy.set.gateway", "policy set <preset...> --client <name-or-id>", "operation-v1:policy.set", gateway, ConsentNone, true, DeferNo),
		command("policy.clear.node", "policy clear", "operation-v1:policy.clear", node, ConsentNone, true, DeferYes),
		command("policy.clear.gateway", "policy clear --client <name-or-id>", "operation-v1:policy.clear", gateway, ConsentNone, true, DeferNo),
		command("dns.show", "dns show", "resource-v1:dns.show", initialized, ConsentNone, false, DeferNo),
		command("dns.set", "dns set <IPv4...>", "operation-v1:dns.set", initialized, ConsentNone, true, DeferNo),
		command("dns.reset", "dns reset", "operation-v1:dns.reset", initialized, ConsentNone, true, DeferNo),
		command("transport.test", "transport test <transport>", "diagnostic-v1:transport.test", node, ConsentNone, false, DeferNo),
		command("transport.switch", "transport switch <transport>", "operation-v1:transport.switch", node, ConsentConfirm, true, DeferYes),
		command("transport.host.show", "transport host show", "resource-v1:transport.host.show", gateway, ConsentNone, false, DeferNo),
		command("transport.host.prepare", "transport host prepare <host>", "operation-v1:transport.host.prepare", gateway, ConsentNone, true, DeferNo),
		command("transport.host.commit", "transport host commit", "operation-v1:transport.host.commit", gateway, ConsentConfirm, true, DeferNo),
		command("transport.host.rollback", "transport host rollback", "operation-v1:transport.host.rollback", gateway, ConsentConfirm, true, DeferNo),
		command("transport.host.recover", "transport host recover <host>", "operation-v1:transport.host.recover", node, ConsentConfirm, true, DeferNo),
		command("expose", "expose <upstream>", "operation-v1:expose", node, ConsentNone, true, DeferYes),
		command("expose.list", "expose list", "collection-v1:expose.list", node, ConsentNone, false, DeferNo),
		command("expose.show", "expose show <name-or-id>", "resource-v1:expose.show", node, ConsentNone, false, DeferNo),
		command("expose.remove", "expose remove <name-or-id>", "operation-v1:expose.remove", node, ConsentConfirm, true, DeferYes),
		command("cert.show", "cert show", "resource-v1:cert.show", gateway, ConsentNone, false, DeferNo),
		command("cert.export", "cert export [output-path]", "export-v1:cert.export", gateway, ConsentNone, true, DeferNo),
		command("cert.rotate", "cert rotate", "operation-v1:cert.rotate", gateway, ConsentConfirm, true, DeferNo),
		command("trust.show", "trust show", "resource-v1:trust.show", gateway, ConsentNone, false, DeferNo),
		command("trust.rotate", "trust rotate", "operation-v1:trust.rotate", gateway, ConsentConfirm, true, DeferNo),
		command("trust.commit", "trust commit", "operation-v1:trust.commit", gateway, ConsentConfirm, true, DeferNo),
		command("trust.rollback", "trust rollback", "operation-v1:trust.rollback", gateway, ConsentConfirm, true, DeferNo),
		command("log.status", "log status", "status-v1:log.status", initialized, ConsentNone, false, DeferNo),
		command("log.enable", "log enable <scope>", "operation-v1:log.enable", initialized, ConsentNone, true, DeferNo),
		command("log.disable", "log disable <scope>", "operation-v1:log.disable", initialized, ConsentNone, true, DeferNo),
		command("backup", "backup [archive-path]", "artifact-v1:backup", gateway, ConsentNone, true, DeferNo),
		command("restore", "restore <archive-path>", "operation-v1:restore", all, ConsentConfirm, true, DeferNo),
		command("update", "update [version]", "operation-v1:update", initialized, ConsentConfirmTypedIfIrreversible, true, DeferNo),
		command("update.rollback", "update rollback", "operation-v1:update.rollback", initialized, ConsentConfirm, true, DeferNo),
		command("uninstall", "uninstall", "operation-v1:uninstall", initialized, ConsentConfirm, true, DeferNo),
		command("purge", "purge", "operation-v1:purge", initialized, ConsentTyped, true, DeferNo),
	}
	secretFlows := map[string]PromptKind{
		"invite":               PromptSecretOutputOnce,
		"join":                 PromptSecretOnce,
		"node.recover.gateway": PromptSecretOutputOnce,
		"node.recover.node":    PromptSecretOnce,
		"backup":               PromptSecretTwice,
		"restore":              PromptSecretOnce,
	}
	for index := range specs {
		if flow, found := secretFlows[specs[index].ID]; found {
			specs[index].SecretFlow = flow
		}
	}
	return specs
}

func command(id, syntax, result string, roles []HostRole, consent ConsentClass, dryRun bool, deferSupport DeferSupport) CommandSpec {
	return CommandSpec{
		ID:             id,
		Syntax:         syntax,
		ResultContract: result,
		Roles:          append([]HostRole(nil), roles...),
		Consent:        consent,
		SecretFlow:     PromptNone,
		DryRun:         dryRun,
		Defer:          deferSupport,
	}
}
