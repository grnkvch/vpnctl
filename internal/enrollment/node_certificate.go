package enrollment

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

var ErrNodeCertificateExpired = errors.New("node control certificate has expired")

type NodeCertificateCondition string

const (
	NodeCertificateHealthy  NodeCertificateCondition = "healthy"
	NodeCertificateExpiring NodeCertificateCondition = "expiring"
	NodeCertificateExpired  NodeCertificateCondition = "expired"
)

// NodeCertificateExpiredError makes the ordinary-rotation boundary machine
// detectable while giving the operator both halves of the recovery flow. The
// immutable node ID is used in the gateway command so the direction stays
// valid across renames and is safe to copy into ordinary output.
type NodeCertificateExpiredError struct {
	NodeID   string
	NotAfter time.Time
}

func (failure *NodeCertificateExpiredError) Error() string {
	if failure == nil {
		return ErrNodeCertificateExpired.Error()
	}
	return fmt.Sprintf(
		"%s: node %s expired at %s; ordinary rotation is unavailable; on the gateway run %q, then on this private node run %q",
		ErrNodeCertificateExpired, failure.NodeID, canonicalTime(failure.NotAfter).Format(time.RFC3339),
		"sudo vpnctl node recover "+failure.NodeID, "sudo vpnctl node recover",
	)
}

func (*NodeCertificateExpiredError) Unwrap() error { return ErrNodeCertificateExpired }

// NodeCertificateHealth is a secret-free projection shared by the focused
// task-9.8 outputs and the complete status/doctor implementations that follow
// in tasks 13.6 and 13.7.
type NodeCertificateHealth struct {
	NodeID               string
	NodeName             string
	CertificateID        string
	Fingerprint          string
	CredentialGeneration uint64
	NotAfter             time.Time
	WarningStartsAt      time.Time
	WarningDays          int
	Condition            NodeCertificateCondition
}

type NodeCertificateReport struct {
	Role            model.Role
	StateGeneration uint64
	Items           []NodeCertificateHealth
}

type NodeCertificateInspector struct {
	state NodeStateReader
	now   func() time.Time
}

func NewNodeCertificateInspector(state NodeStateReader, now func() time.Time) (*NodeCertificateInspector, error) {
	if state == nil {
		return nil, fmt.Errorf("node certificate inspector state reader is required")
	}
	if now == nil {
		now = time.Now
	}
	return &NodeCertificateInspector{state: state, now: now}, nil
}

// Inspect is passive. It reads validated state and never probes a peer,
// renews a certificate, or records desired state.
func (inspector *NodeCertificateInspector) Inspect() (NodeCertificateReport, error) {
	if inspector == nil || inspector.state == nil || inspector.now == nil {
		return NodeCertificateReport{}, fmt.Errorf("node certificate inspector is incomplete")
	}
	state, err := inspector.state.Load()
	if err != nil {
		return NodeCertificateReport{}, fmt.Errorf("load node certificate status: %w", err)
	}
	return inspectNodeCertificates(state, inspector.now())
}

func inspectNodeCertificates(state model.State, now time.Time) (NodeCertificateReport, error) {
	if err := state.Validate(); err != nil {
		return NodeCertificateReport{}, fmt.Errorf("validate node certificate status: %w", err)
	}
	if state.Host.Role != model.RoleGateway && state.Host.Role != model.RoleNode {
		return NodeCertificateReport{}, fmt.Errorf("node certificate status requires initialized gateway or node state")
	}
	report := NodeCertificateReport{
		Role: state.Host.Role, StateGeneration: state.Generation, Items: []NodeCertificateHealth{},
	}
	for _, node := range state.Nodes {
		if node.Lifecycle != model.LifecycleActive {
			continue
		}
		certificate, err := currentNodeControlCertificate(state, node)
		if err != nil {
			return NodeCertificateReport{}, err
		}
		condition, warningStartsAt := evaluateNodeCertificate(certificate, now)
		report.Items = append(report.Items, NodeCertificateHealth{
			NodeID: node.ID, NodeName: node.Name, CertificateID: certificate.ID,
			Fingerprint: certificate.Fingerprint, CredentialGeneration: node.CredentialGeneration,
			NotAfter: certificate.NotAfter, WarningStartsAt: warningStartsAt,
			WarningDays: control.ControlWarningDays, Condition: condition,
		})
	}
	sort.Slice(report.Items, func(left, right int) bool {
		leftName, rightName := strings.ToLower(report.Items[left].NodeName), strings.ToLower(report.Items[right].NodeName)
		if leftName != rightName {
			return leftName < rightName
		}
		return report.Items[left].NodeID < report.Items[right].NodeID
	})
	return report, nil
}

func evaluateNodeCertificate(certificate model.Certificate, now time.Time) (NodeCertificateCondition, time.Time) {
	now = canonicalTime(now)
	warningStartsAt := canonicalTime(certificate.NotAfter.Add(-control.ControlRenewalWindow))
	if !now.Before(canonicalTime(certificate.NotAfter)) {
		return NodeCertificateExpired, warningStartsAt
	}
	if !now.Before(warningStartsAt) {
		return NodeCertificateExpiring, warningStartsAt
	}
	return NodeCertificateHealthy, warningStartsAt
}

func currentNodeControlCertificate(state model.State, node model.Node) (model.Certificate, error) {
	var current *model.Certificate
	for index := range state.Certificates {
		certificate := &state.Certificates[index]
		if certificate.Kind != model.CertificateControlNode || certificate.OwnerID != node.ID ||
			certificate.EffectiveCredentialGeneration() != node.CredentialGeneration {
			continue
		}
		if current != nil {
			return model.Certificate{}, fmt.Errorf("node %s has multiple current control certificate records", node.ID)
		}
		current = certificate
	}
	if current == nil {
		return model.Certificate{}, fmt.Errorf("node %s has no current control certificate metadata", node.ID)
	}
	return *current, nil
}

func refuseExpiredNodeRotation(state model.State, node model.Node, now time.Time) error {
	certificate, err := currentNodeControlCertificate(state, node)
	if err != nil {
		return err
	}
	condition, _ := evaluateNodeCertificate(certificate, now)
	if condition != NodeCertificateExpired {
		return nil
	}
	return &NodeCertificateExpiredError{NodeID: node.ID, NotAfter: certificate.NotAfter}
}
