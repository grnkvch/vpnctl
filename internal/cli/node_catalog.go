package cli

import (
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

// NodeListOutput and NodeShowOutput are the only CLI projections of gateway
// node state. They deliberately copy the enrollment package's secret-free
// views into output.SafeObject instead of exposing model records directly.
func NodeListOutput(list enrollment.NodeList) output.Result {
	items := make([]output.SafeObject, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, nodeViewOutput(item))
	}
	return output.NewResult("node.list", output.StatusOK, output.CategorySuccess, output.SafeObject{"items": items})
}

func NodeShowOutput(show enrollment.NodeShow) output.Result {
	result := output.NewResult("node.show", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"resource": nodeViewOutput(show.Resource),
	})
	if show.Resource.ID != "" {
		result.ResourceIDs["node_id"] = show.Resource.ID
	}
	return result
}

func nodeViewOutput(view enrollment.NodeView) output.SafeObject {
	transports := make([]output.SafeObject, 0, len(view.Transports))
	for _, record := range view.Transports {
		transport := output.SafeObject{
			"kind": string(record.Kind), "state": string(record.State),
			"protocol": string(record.Protocol), "port": record.Port,
		}
		if record.HandshakeHost != "" {
			transport["handshake_host"] = record.HandshakeHost
		}
		transports = append(transports, transport)
	}
	resource := output.SafeObject{
		"id": view.ID, "name": view.Name, "lifecycle": string(view.Lifecycle),
		"overlay_ipv4": view.OverlayIPv4, "assigned_presets": append([]string{}, view.AssignedPresets...),
		"credential_generation": view.CredentialGeneration, "policy_generation": view.PolicyGeneration,
		"active_transport": string(view.ActiveTransport), "transports": transports,
		"control_certificate": output.SafeObject{
			"fingerprint": view.ControlCertificate.Fingerprint,
			"not_after":   view.ControlCertificate.NotAfter.UTC().Format(time.RFC3339),
			"generation":  view.ControlCertificate.Generation,
		},
		"created_at": view.CreatedAt.UTC().Format(time.RFC3339),
	}
	if view.RevokedAt != nil {
		resource["revoked_at"] = view.RevokedAt.UTC().Format(time.RFC3339)
	}
	return resource
}
