package transport

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const transportSwitchIntentVersion = "v1"

type SwitchMutationAction string

const (
	SwitchMutationRegister SwitchMutationAction = "register"
	SwitchMutationFinalize SwitchMutationAction = "finalize"
)

var switchOperationSteps = []string{
	"stage", "activate-private", "confirm-private", "publish-public", "drain", "finalize",
}

func SwitchOperationStepNames() []string {
	return append([]string(nil), switchOperationSteps...)
}

// SwitchIntentTarget is the non-secret, versioned identity retained in a
// gateway Operation. A node transport is identified by owner plus kind, while
// the node generations let a later cross-host executor reject a stale local
// state without guessing.
type SwitchIntentTarget struct {
	NodeID                 string
	Target                 model.TransportKind
	ExpectedNodeGeneration uint64
	DesiredNodeGeneration  uint64
}

type DeferredSwitchRequest struct {
	Action                 SwitchMutationAction `json:"action"`
	Current                model.TransportKind  `json:"current"`
	Target                 model.TransportKind  `json:"target"`
	ExpectedNodeGeneration uint64               `json:"expected_node_generation"`
	DesiredNodeGeneration  uint64               `json:"desired_node_generation,omitempty"`
	OperationID            string               `json:"operation_id,omitempty"`
}

func (request DeferredSwitchRequest) IntentTarget(nodeID string) (SwitchIntentTarget, error) {
	if !isTransportKind(request.Current) || !isTransportKind(request.Target) || request.Current == request.Target {
		return SwitchIntentTarget{}, fmt.Errorf("deferred transport switch requires different explicit current and target transports")
	}
	return NewSwitchIntentTarget(nodeID, request.Target, request.ExpectedNodeGeneration)
}

func (request DeferredSwitchRequest) ValidateRegistration(nodeID string, expectedGatewayGeneration uint64, requestID string) (SwitchIntentTarget, error) {
	intent, err := request.IntentTarget(nodeID)
	if err != nil || request.Action != SwitchMutationRegister || request.DesiredNodeGeneration != 0 || request.OperationID != "" {
		return SwitchIntentTarget{}, fmt.Errorf("deferred transport switch registration is invalid")
	}
	wantRequestID, err := SwitchRequestID(intent, request.Current, expectedGatewayGeneration)
	if err != nil || wantRequestID != requestID {
		return SwitchIntentTarget{}, fmt.Errorf("deferred transport switch registration identity is invalid")
	}
	return intent, nil
}

func (request DeferredSwitchRequest) ValidateFinalization(nodeID string, expectedGatewayGeneration uint64, requestID string) (SwitchIntentTarget, error) {
	intent, err := request.IntentTarget(nodeID)
	if err != nil || request.Action != SwitchMutationFinalize || request.OperationID == "" ||
		request.DesiredNodeGeneration != intent.DesiredNodeGeneration || !isTransportKind(request.Current) ||
		request.Current == request.Target {
		return SwitchIntentTarget{}, fmt.Errorf("transport switch finalization is invalid")
	}
	if err := model.ValidateResourceID(request.OperationID); err != nil {
		return SwitchIntentTarget{}, fmt.Errorf("transport switch finalization operation ID is invalid")
	}
	wantRequestID, err := SwitchFinalizeRequestID(request.OperationID, intent.DesiredNodeGeneration, expectedGatewayGeneration)
	if err != nil || wantRequestID != requestID {
		return SwitchIntentTarget{}, fmt.Errorf("transport switch finalization identity is invalid")
	}
	return intent, nil
}

type DeferredSwitchReceipt struct {
	OperationID              string              `json:"operation_id"`
	RequestID                string              `json:"request_id"`
	NodeID                   string              `json:"node_id"`
	Current                  model.TransportKind `json:"current"`
	Target                   model.TransportKind `json:"target"`
	GatewayGeneration        uint64              `json:"gateway_generation"`
	DesiredGatewayGeneration uint64              `json:"desired_gateway_generation"`
	ExpectedNodeGeneration   uint64              `json:"expected_node_generation"`
	DesiredNodeGeneration    uint64              `json:"desired_node_generation"`
}

type FinalizedSwitchReceipt struct {
	OperationID               string              `json:"operation_id"`
	RequestID                 string              `json:"request_id"`
	NodeID                    string              `json:"node_id"`
	Previous                  model.TransportKind `json:"previous"`
	Active                    model.TransportKind `json:"active"`
	ExpectedGatewayGeneration uint64              `json:"expected_gateway_generation"`
	GatewayGeneration         uint64              `json:"gateway_generation"`
	ExpectedNodeGeneration    uint64              `json:"expected_node_generation"`
	DesiredNodeGeneration     uint64              `json:"desired_node_generation"`
}

func (receipt FinalizedSwitchReceipt) Validate() error {
	if err := model.ValidateResourceID(receipt.OperationID); err != nil {
		return fmt.Errorf("transport switch operation ID: %w", err)
	}
	if err := model.ValidateResourceID(receipt.RequestID); err != nil {
		return fmt.Errorf("transport switch finalization request ID: %w", err)
	}
	if err := model.ValidateResourceID(receipt.NodeID); err != nil {
		return fmt.Errorf("transport switch node ID: %w", err)
	}
	pendingNodeGeneration, pendingErr := model.NextGeneration(receipt.ExpectedNodeGeneration)
	desiredNodeGeneration, desiredErr := model.NextGeneration(pendingNodeGeneration)
	wantRequestID, requestErr := SwitchFinalizeRequestID(
		receipt.OperationID, receipt.DesiredNodeGeneration, receipt.ExpectedGatewayGeneration,
	)
	if pendingErr != nil || desiredErr != nil || requestErr != nil ||
		desiredNodeGeneration != receipt.DesiredNodeGeneration || wantRequestID != receipt.RequestID ||
		!isTransportKind(receipt.Previous) || !isTransportKind(receipt.Active) || receipt.Previous == receipt.Active ||
		receipt.ExpectedGatewayGeneration == 0 || receipt.GatewayGeneration <= receipt.ExpectedGatewayGeneration {
		return fmt.Errorf("transport switch finalization receipt is invalid")
	}
	return nil
}

func (receipt DeferredSwitchReceipt) Validate() error {
	if err := model.ValidateResourceID(receipt.OperationID); err != nil {
		return fmt.Errorf("transport switch operation ID: %w", err)
	}
	if err := model.ValidateResourceID(receipt.RequestID); err != nil {
		return fmt.Errorf("transport switch request ID: %w", err)
	}
	wantOperationID, err := SwitchOperationID(receipt.RequestID)
	if err != nil || wantOperationID != receipt.OperationID {
		return fmt.Errorf("transport switch operation and request IDs are inconsistent")
	}
	intent, err := NewSwitchIntentTarget(receipt.NodeID, receipt.Target, receipt.ExpectedNodeGeneration)
	if err != nil || intent.DesiredNodeGeneration != receipt.DesiredNodeGeneration ||
		!isTransportKind(receipt.Current) || receipt.Current == receipt.Target || receipt.GatewayGeneration < 2 {
		return fmt.Errorf("deferred transport switch receipt is invalid")
	}
	desiredGateway, err := model.NextGeneration(receipt.GatewayGeneration)
	if err != nil || desiredGateway != receipt.DesiredGatewayGeneration {
		return fmt.Errorf("deferred transport switch gateway generations are inconsistent")
	}
	return nil
}

func NewSwitchIntentTarget(nodeID string, target model.TransportKind, expectedNodeGeneration uint64) (SwitchIntentTarget, error) {
	pending, err := model.NextGeneration(expectedNodeGeneration)
	if err != nil {
		return SwitchIntentTarget{}, fmt.Errorf("desired node %w", err)
	}
	desired, err := model.NextGeneration(pending)
	if err != nil {
		return SwitchIntentTarget{}, fmt.Errorf("desired node %w", err)
	}
	value := SwitchIntentTarget{
		NodeID: nodeID, Target: target,
		ExpectedNodeGeneration: expectedNodeGeneration, DesiredNodeGeneration: desired,
	}
	if err := value.Validate(); err != nil {
		return SwitchIntentTarget{}, err
	}
	return value, nil
}

func ParseSwitchIntentTarget(value string) (SwitchIntentTarget, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 5 || parts[0] != transportSwitchIntentVersion {
		return SwitchIntentTarget{}, fmt.Errorf("transport switch intent target is invalid")
	}
	expected, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil || strconv.FormatUint(expected, 10) != parts[3] {
		return SwitchIntentTarget{}, fmt.Errorf("transport switch expected node generation is invalid")
	}
	desired, err := strconv.ParseUint(parts[4], 10, 64)
	if err != nil || strconv.FormatUint(desired, 10) != parts[4] {
		return SwitchIntentTarget{}, fmt.Errorf("transport switch desired node generation is invalid")
	}
	result := SwitchIntentTarget{
		NodeID: parts[1], Target: model.TransportKind(parts[2]),
		ExpectedNodeGeneration: expected, DesiredNodeGeneration: desired,
	}
	if err := result.Validate(); err != nil {
		return SwitchIntentTarget{}, err
	}
	if result.String() != value {
		return SwitchIntentTarget{}, fmt.Errorf("transport switch intent target is not canonical")
	}
	return result, nil
}

func (target SwitchIntentTarget) Validate() error {
	if err := model.ValidateResourceID(target.NodeID); err != nil {
		return fmt.Errorf("transport switch node ID: %w", err)
	}
	if !isTransportKind(target.Target) {
		return fmt.Errorf("transport switch target is invalid")
	}
	if target.ExpectedNodeGeneration == 0 {
		return fmt.Errorf("transport switch expected node generation must be positive")
	}
	pending, err := model.NextGeneration(target.ExpectedNodeGeneration)
	if err != nil {
		return fmt.Errorf("transport switch node generations are inconsistent")
	}
	desired, err := model.NextGeneration(pending)
	if err != nil || desired != target.DesiredNodeGeneration {
		return fmt.Errorf("transport switch node generations are inconsistent")
	}
	return nil
}

func (target SwitchIntentTarget) String() string {
	return fmt.Sprintf("%s:%s:%s:%d:%d", transportSwitchIntentVersion, target.NodeID, target.Target,
		target.ExpectedNodeGeneration, target.DesiredNodeGeneration)
}

// SwitchRequestID is stable for the exact reviewed local/gateway generations.
// Retrying after a lost response therefore reaches the controller's durable
// idempotency record instead of registering a second operation.
func SwitchRequestID(target SwitchIntentTarget, current model.TransportKind, expectedGatewayGeneration uint64) (string, error) {
	if err := target.Validate(); err != nil || !isTransportKind(current) || current == target.Target || expectedGatewayGeneration == 0 {
		return "", fmt.Errorf("transport switch request identity input is invalid")
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("vpnctl-v2:transport-switch:%s:%s:%d", target.String(), current, expectedGatewayGeneration)))
	return uuidFromDigest(digest, 4), nil
}

// SwitchOperationID is derived from the stable request ID. It remains known to
// the node even when the committed gateway response is lost and only the
// controller's compact idempotency receipt survives.
func SwitchOperationID(requestID string) (string, error) {
	if err := model.ValidateResourceID(requestID); err != nil {
		return "", fmt.Errorf("transport switch request ID: %w", err)
	}
	digest := sha256.Sum256([]byte("vpnctl-v2:transport-switch-operation:" + requestID))
	return uuidFromDigest(digest, 4), nil
}

// SwitchFinalizeRequestID is stable for the exact retained operation and the
// node/gateway generations proven by apply. It is deliberately distinct from
// the registration request so both commits have independent idempotency
// records.
func SwitchFinalizeRequestID(operationID string, desiredNodeGeneration, expectedGatewayGeneration uint64) (string, error) {
	if err := model.ValidateResourceID(operationID); err != nil || desiredNodeGeneration == 0 || expectedGatewayGeneration == 0 {
		return "", fmt.Errorf("transport switch finalization identity input is invalid")
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("vpnctl-v2:transport-switch-finalize:%s:%d:%d",
		operationID, desiredNodeGeneration, expectedGatewayGeneration)))
	return uuidFromDigest(digest, 4), nil
}

func uuidFromDigest(digest [sha256.Size]byte, version byte) string {
	value := digest[:16]
	value[6] = (value[6] & 0x0f) | version<<4
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
