package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func ExposeListOutput(list operations.ExposeList) (output.Result, error) {
	items := make([]output.SafeObject, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, exposeViewOutput(item))
	}
	result := output.NewResult("expose.list", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"items": items, "generation": list.LocalStateGeneration,
		"gateway_reachable":  list.GatewayReachable,
		"gateway_generation": list.GatewayStateGeneration,
	})
	if !list.GatewayReachable {
		result.Status = output.StatusDegraded
		result.ExitCategory = output.CategoryUnavailable
		result.Warnings = append(result.Warnings, output.Message{
			Code: "gateway_unavailable", Message: "Gateway certificate availability could not be refreshed.",
		})
	}
	return result, result.Validate()
}

func ExposeShowOutput(show operations.ExposeShow) (output.Result, error) {
	result := output.NewResult("expose.show", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"resource": exposeViewOutput(show.Resource), "generation": show.LocalStateGeneration,
		"gateway_reachable":  show.GatewayReachable,
		"gateway_generation": show.GatewayStateGeneration,
	})
	if show.Resource.ID != "" {
		result.ResourceIDs["expose_id"] = show.Resource.ID
	}
	if !show.GatewayReachable {
		result.Status = output.StatusDegraded
		result.ExitCategory = output.CategoryUnavailable
		result.Warnings = append(result.Warnings, output.Message{
			Code: "gateway_unavailable", Message: "Gateway certificate availability could not be refreshed.",
		})
		return result, result.Validate()
	}
	if show.Resource.Certificate.Available {
		result.Data["output_path"] = show.Resource.Certificate.OutputPath
		result.Data["scp_command"] = "scp root@" + show.Resource.Certificate.PublicIPv4 + ":" +
			show.Resource.Certificate.OutputPath + " ./" + filepath.Base(show.Resource.Certificate.OutputPath)
	}
	var publicURL string
	if err := show.PublicURL(func(value string) error {
		publicURL = value
		return nil
	}); err != nil {
		return output.Result{}, fmt.Errorf("read expose public URL: %w", err)
	}
	sensitiveURL, err := output.NewSensitivePath(publicURL)
	if err != nil {
		return output.Result{}, err
	}
	if err := result.AddHumanSensitivePath("public_url", sensitiveURL); err != nil {
		return output.Result{}, err
	}
	return result, result.Validate()
}

func exposeViewOutput(view operations.ExposeView) output.SafeObject {
	certificate := output.SafeObject{"available": view.Certificate.Available}
	if view.Certificate.ID != "" {
		certificate["id"] = view.Certificate.ID
		certificate["fingerprint"] = view.Certificate.Fingerprint
		certificate["not_after"] = view.Certificate.NotAfter.UTC().Format(time.RFC3339)
		certificate["generation"] = view.Certificate.Generation
	}
	return output.SafeObject{
		"id": view.ID, "name": view.Name, "upstream": view.Upstream,
		"route_mode": string(view.RouteMode), "body_limit_bytes": view.BodyLimitBytes,
		"upstream_timeout_seconds": view.UpstreamTimeoutSeconds,
		"concurrent_requests":      view.ConcurrentRequests, "state": string(view.State),
		"generation": view.Generation, "created_at": view.CreatedAt.UTC().Format(time.RFC3339),
		"public_certificate": certificate,
	}
}
