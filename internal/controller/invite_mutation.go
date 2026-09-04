package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

// GatewayInviteMutationDispatcher keeps invite secret generation and the
// authoritative state commit inside the controller's serialized mutation
// boundary. The one-time token is returned only over the root-only Unix
// socket and is never persisted.
type GatewayInviteMutationDispatcher struct {
	entropy io.Reader
	now     func() time.Time
}

type GatewayInviteIssuePayload struct {
	Plan enrollment.InviteIssuePlan `json:"plan"`
}

type GatewayInviteIssueData struct {
	Invite enrollment.InviteStatus `json:"invite"`
	Token  string                  `json:"token"`
}

type GatewayInviteCancelPayload struct {
	InviteID                string `json:"invite_id"`
	ExpectedStateGeneration uint64 `json:"expected_state_generation"`
}

type GatewayInviteCancelData struct {
	InviteID string `json:"invite_id"`
	NodeName string `json:"node_name"`
	Changed  bool   `json:"changed"`
}

func NewGatewayInviteMutationDispatcher(entropy io.Reader, now func() time.Time) *GatewayInviteMutationDispatcher {
	return &GatewayInviteMutationDispatcher{entropy: entropy, now: now}
}

func (dispatcher *GatewayInviteMutationDispatcher) Prepare(
	ctx context.Context,
	state model.State,
	operation string,
	payload json.RawMessage,
) (PreparedMutation, error) {
	if dispatcher == nil || ctx == nil {
		return PreparedMutation{}, fmt.Errorf("gateway invite mutation dispatcher is incomplete")
	}
	memory := &gatewayInviteState{current: state}
	manager, err := enrollment.NewInviteManager(memory, dispatcher.entropy, dispatcher.now)
	if err != nil {
		return PreparedMutation{}, err
	}
	switch operation {
	case enrollment.InviteIssueOperation:
		var request GatewayInviteIssuePayload
		if err := decodeGatewayInvitePayload(payload, &request); err != nil {
			return PreparedMutation{}, err
		}
		result, err := manager.CommitIssue(ctx, request.Plan)
		if err != nil {
			return PreparedMutation{}, err
		}
		if result.Token == nil || !memory.saved {
			return PreparedMutation{}, fmt.Errorf("invite issue did not produce an authoritative candidate")
		}
		defer result.Token.Destroy()
		data := GatewayInviteIssueData{Invite: result.Invite}
		if err := result.Token.Use(func(token []byte) error {
			data.Token = string(token)
			return nil
		}); err != nil {
			return PreparedMutation{}, err
		}
		encoded, err := json.Marshal(data)
		data.Token = ""
		if err != nil {
			return PreparedMutation{}, fmt.Errorf("encode invite issue response: %w", err)
		}
		return stateOnlyPreparedMutation(memory.current, encoded, true), nil
	case enrollment.InviteCancelOperation:
		var request GatewayInviteCancelPayload
		if err := decodeGatewayInvitePayload(payload, &request); err != nil {
			return PreparedMutation{}, err
		}
		if request.ExpectedStateGeneration == 0 || request.ExpectedStateGeneration != state.Generation {
			return PreparedMutation{}, fmt.Errorf("%w: expected state generation changed", enrollment.ErrInvitePlanStale)
		}
		plan, err := manager.PlanCancel(request.InviteID)
		if err != nil {
			return PreparedMutation{}, err
		}
		result, err := manager.CommitCancel(plan)
		if err != nil {
			return PreparedMutation{}, err
		}
		encoded, err := json.Marshal(GatewayInviteCancelData{
			InviteID: result.InviteID, NodeName: result.NodeName, Changed: result.Changed,
		})
		if err != nil {
			return PreparedMutation{}, fmt.Errorf("encode invite cancellation response: %w", err)
		}
		if !result.Changed {
			return stateOnlyPreparedMutation(state, encoded, false), nil
		}
		if !memory.saved {
			return PreparedMutation{}, fmt.Errorf("invite cancellation did not produce an authoritative candidate")
		}
		return stateOnlyPreparedMutation(memory.current, encoded, true), nil
	default:
		return PreparedMutation{}, fmt.Errorf("unsupported gateway invite operation")
	}
}

func decodeGatewayInvitePayload(payload json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode gateway invite mutation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode gateway invite mutation: trailing data")
	}
	return nil
}

func stateOnlyPreparedMutation(candidate model.State, data json.RawMessage, changed bool) PreparedMutation {
	return PreparedMutation{
		Candidate: candidate, Data: data, Changed: changed,
		Apply:    func(context.Context) error { return nil },
		Rollback: func(context.Context) error { return nil },
	}
}

type gatewayInviteState struct {
	current model.State
	saved   bool
}

func (state *gatewayInviteState) Load() (model.State, error) {
	if state == nil {
		return model.State{}, fmt.Errorf("gateway invite state is unavailable")
	}
	return state.current, nil
}

func (state *gatewayInviteState) Save(expectedGeneration uint64, candidate model.State) error {
	if state == nil || state.saved || state.current.Generation != expectedGeneration {
		return fmt.Errorf("gateway invite state generation changed")
	}
	if err := model.ValidateTransition(state.current, candidate); err != nil {
		return err
	}
	state.current = candidate
	state.saved = true
	return nil
}
