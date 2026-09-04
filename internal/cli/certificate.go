package cli

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type certificateStateStore interface {
	Load() (model.State, error)
}

var (
	certificateSystemPaths = store.DefaultPaths
	certificateLoadRole    = loadSystemHostRole
	certificateNewState    = func(paths store.Paths) (certificateStateStore, error) { return store.NewStateStore(paths) }
	certificateNewSecrets  = func(paths store.Paths) (ingress.PublicCertificateSecretStore, error) {
		return store.NewSecretStore(paths)
	}
	certificateNow = time.Now
)

func isCertificateInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" {
			continue
		}
		return argument == "cert"
	}
	return false
}

type certificateArguments struct {
	Action     string
	OutputPath string
	JSON       bool
	ShowHelp   bool
	CommandID  string
}

func executeCertificate(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseCertificateArguments(args)
	if parsed.ShowHelp {
		printCertificateHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "cert failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitCertificateFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := certificateSystemPaths()
	role, err := certificateLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitCertificateFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "cert requires an initialized gateway")
	}
	if role != RoleGateway {
		return emitCertificateFailure(emitter, parsed.CommandID, output.CategoryValidation, "unsupported_role", "public certificate commands are gateway-only")
	}
	stateSource, err := certificateNewState(paths)
	if err != nil {
		return emitCertificateFailure(emitter, parsed.CommandID, output.CategoryInternal, "certificate_state_unavailable", "vpnctl could not open authoritative state")
	}
	var result output.Result
	err = V2CommandRegistry().Dispatch(parsed.CommandID, role, func(CommandSpec) error {
		state, err := stateSource.Load()
		if err != nil {
			return fmt.Errorf("load authoritative certificate state: %w", err)
		}
		switch parsed.Action {
		case "show":
			status, err := ingress.InspectPublicCertificate(state, certificateNow())
			if err != nil {
				return err
			}
			result = publicCertificateShowResult(status)
			return nil
		case "export":
			secrets, err := certificateNewSecrets(paths)
			if err != nil {
				return fmt.Errorf("open public certificate source: %w", err)
			}
			destination := parsed.OutputPath
			if destination == "" {
				destination = ingress.DefaultPublicCertificateExportPath(paths.ExportsDir)
			}
			exported, err := ingress.ExportPublicCertificate(state, secrets, destination)
			if err != nil {
				return err
			}
			result = publicCertificateExportResult(state.Host.PublicIPv4, exported)
			return nil
		default:
			return fmt.Errorf("unsupported certificate action")
		}
	})
	if err != nil {
		category, code, message := classifyCertificateError(err)
		return emitCertificateFailure(emitter, parsed.CommandID, category, code, message)
	}
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseCertificateArguments(args []string) (certificateArguments, error) {
	parsed := certificateArguments{CommandID: "cert.show"}
	positionals := make([]string, 0, len(args))
	for _, argument := range args {
		switch argument {
		case "--json":
			if parsed.JSON {
				return parsed, fmt.Errorf("--json may be supplied only once")
			}
			parsed.JSON = true
		case "-h", "--help", "help":
			parsed.ShowHelp = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported cert option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.ShowHelp {
		return parsed, nil
	}
	if len(positionals) == 0 || positionals[0] != "cert" {
		return parsed, fmt.Errorf("cert command is missing")
	}
	if len(positionals) < 2 {
		return parsed, fmt.Errorf("cert requires show or export")
	}
	parsed.Action = positionals[1]
	parsed.CommandID = "cert." + parsed.Action
	switch parsed.Action {
	case "show":
		if len(positionals) != 2 {
			return parsed, fmt.Errorf("cert show accepts no arguments")
		}
	case "export":
		if len(positionals) > 3 {
			return parsed, fmt.Errorf("cert export accepts at most one output path")
		}
		if len(positionals) == 3 {
			parsed.OutputPath = positionals[2]
			if !filepath.IsAbs(parsed.OutputPath) || filepath.Clean(parsed.OutputPath) != parsed.OutputPath {
				return parsed, fmt.Errorf("cert export output path must be clean and absolute")
			}
		}
	default:
		return parsed, fmt.Errorf("unsupported cert action %s", parsed.Action)
	}
	return parsed, nil
}

func publicCertificateShowResult(status ingress.PublicCertificateStatus) output.Result {
	resultStatus := output.StatusOK
	category := output.CategorySuccess
	if status.Condition == ingress.PublicCertificateExpired {
		resultStatus = output.StatusDegraded
		category = output.CategoryUnavailable
	}
	sans := make(output.SafeList, len(status.SANs))
	for index, value := range status.SANs {
		sans[index] = value
	}
	result := output.NewResult("cert.show", resultStatus, category, output.SafeObject{
		"public_ipv4": status.PublicIPv4, "certificate_id": status.CertificateID,
		"fingerprint": status.Fingerprint, "serial_hex": status.SerialHex,
		"subject": status.Subject, "sans": sans,
		"not_before": status.NotBefore.UTC().Format(time.RFC3339), "not_after": status.NotAfter.UTC().Format(time.RFC3339),
		"warning_starts_at": status.WarningStartsAt.UTC().Format(time.RFC3339), "warning_days": status.WarningDays,
		"generation": status.Generation, "condition": string(status.Condition),
	})
	result.ResourceIDs["certificate_id"] = status.CertificateID
	if status.Condition == ingress.PublicCertificateHealthy {
		return result
	}
	code := "public_certificate_expiring"
	message := fmt.Sprintf("Public ingress certificate expires at %s.", status.NotAfter.UTC().Format(time.RFC3339))
	if status.Condition == ingress.PublicCertificateExpired {
		code = "public_certificate_expired"
		message = fmt.Sprintf("Public ingress certificate expired at %s.", status.NotAfter.UTC().Format(time.RFC3339))
	}
	resourceIDs := map[string]string{"certificate_id": status.CertificateID}
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message, ResourceIDs: resourceIDs})
	result.RequiresAction = append(result.RequiresAction, output.Action{
		Code: "rotate_public_certificate", Message: "Rotate the public certificate and re-register every external webhook that trusts it.",
		Command: "sudo vpnctl cert rotate", ResourceIDs: resourceIDs,
	})
	return result
}

func publicCertificateExportResult(publicIPv4 string, exported ingress.PublicCertificateExport) output.Result {
	result := output.NewResult("cert.export", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": exported.Changed, "output_path": exported.Path, "fingerprint": exported.Fingerprint,
		"scp_command": "scp root@" + publicIPv4 + ":" + exported.Path + " ./" + filepath.Base(exported.Path),
	})
	return result
}

func classifyCertificateError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ingress.ErrPublicCertificateExported):
		return output.CategoryConflict, "certificate_export_exists", "public certificate export already exists with different content"
	case errors.Is(err, ingress.ErrPublicCertificateUnsafePath), errors.Is(err, ingress.ErrPublicCertificateInvalid), errors.Is(err, ingress.ErrPublicCertificateNotFound), errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "certificate_invalid", "public ingress certificate state or destination is invalid"
	default:
		return output.CategoryInternal, "certificate_internal_error", "vpnctl could not inspect or export the public certificate"
	}
}

func emitCertificateFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, warningCode, warningMessage string) int {
	if commandID != "cert.show" && commandID != "cert.export" {
		commandID = "cert.show"
	}
	result := output.NewResult(commandID, output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printCertificateHelp(writer io.Writer) {
	fmt.Fprint(writer, `Inspect or export the gateway public ingress certificate.

Usage:
  vpnctl cert show [--json]
  vpnctl cert export [absolute-output-path] [--json]

Export writes only the public PEM certificate. The private key remains in the
root-only vpnctl secret store and is never printed.
`)
}
