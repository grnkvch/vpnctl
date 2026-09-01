package cli

// PromptKind identifies a v2 interactive input contract.
type PromptKind string

const (
	PromptNone             PromptKind = "none"
	PromptConfirm          PromptKind = "confirm"
	PromptTyped            PromptKind = "typed"
	PromptSecretOnce       PromptKind = "secret_once"
	PromptSecretTwice      PromptKind = "secret_twice"
	PromptSecretOutputOnce PromptKind = "secret_output_once"
)

// PromptRequest contains only channel and global-option facts. Command-specific
// code selects the appropriate PromptKind after rendering its impact plan.
type PromptRequest struct {
	Kind   PromptKind `json:"kind"`
	HasTTY bool       `json:"has_tty"`
	Yes    bool       `json:"yes"`
	DryRun bool       `json:"dry_run"`
}

// PromptDecision is deterministic and contains no prompt or secret content.
type PromptDecision struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
	Hidden  bool   `json:"hidden"`
	Reads   int    `json:"reads"`
	Reason  string `json:"reason"`
}

// ResolvePrompt applies the frozen v2 TTY, --yes, and --dry-run rules.
func ResolvePrompt(request PromptRequest) PromptDecision {
	if request.DryRun {
		switch request.Kind {
		case PromptConfirm, PromptTyped, PromptSecretTwice, PromptSecretOutputOnce:
			return proceedWithoutPrompt()
		}
	}

	switch request.Kind {
	case PromptNone:
		return proceedWithoutPrompt()
	case PromptConfirm:
		if request.Yes {
			return proceedWithoutPrompt()
		}
		if !request.HasTTY {
			return refusePrompt("confirmation_requires_tty_or_yes")
		}
		return PromptDecision{Action: "prompt", Channel: "/dev/tty", Reads: 1}
	case PromptTyped:
		if !request.HasTTY {
			return refusePrompt("typed_confirmation_requires_tty")
		}
		return PromptDecision{Action: "prompt", Channel: "/dev/tty", Reads: 1}
	case PromptSecretOnce:
		if !request.HasTTY {
			return refusePrompt("secret_input_requires_tty")
		}
		return PromptDecision{Action: "prompt", Channel: "/dev/tty", Hidden: true, Reads: 1}
	case PromptSecretTwice:
		if !request.HasTTY {
			return refusePrompt("secret_input_requires_tty")
		}
		return PromptDecision{Action: "prompt", Channel: "/dev/tty", Hidden: true, Reads: 2}
	case PromptSecretOutputOnce:
		if !request.HasTTY {
			return refusePrompt("secret_output_requires_tty")
		}
		return PromptDecision{Action: "write", Channel: "/dev/tty", Reads: 0}
	default:
		return refusePrompt("unknown_prompt_kind")
	}
}

func proceedWithoutPrompt() PromptDecision {
	return PromptDecision{Action: "proceed", Channel: "none"}
}

func refusePrompt(reason string) PromptDecision {
	return PromptDecision{Action: "refuse", Channel: "none", Reason: reason}
}
