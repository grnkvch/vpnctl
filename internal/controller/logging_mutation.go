package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type GatewayLoggingMutationDispatcher struct {
	paths   store.Paths
	now     func() time.Time
	newUUID model.UUIDGenerator
}

type gatewayLoggingEnablePayload struct {
	Scope           model.LogScope `json:"scope"`
	Level           model.LogLevel `json:"level"`
	DurationSeconds int64          `json:"duration_seconds"`
	File            bool           `json:"file"`
}

type gatewayLoggingDisablePayload struct {
	Scope model.LogScope `json:"scope"`
}

func NewGatewayLoggingMutationDispatcher(paths store.Paths, now func() time.Time, newUUID model.UUIDGenerator) (*GatewayLoggingMutationDispatcher, error) {
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("gateway logging mutation paths are invalid")
	}
	if now == nil {
		now = time.Now
	}
	if newUUID == nil {
		newUUID = model.NewUUID
	}
	return &GatewayLoggingMutationDispatcher{paths: paths, now: now, newUUID: newUUID}, nil
}

func (dispatcher *GatewayLoggingMutationDispatcher) Dispatch(context.Context, model.State, string, json.RawMessage) (model.State, json.RawMessage, error) {
	return model.State{}, nil, fmt.Errorf("gateway logging mutations require the prepared transaction path")
}

func (dispatcher *GatewayLoggingMutationDispatcher) Prepare(ctx context.Context, state model.State, operation string, raw json.RawMessage) (PreparedMutation, error) {
	if ctx == nil || dispatcher == nil || dispatcher.now == nil || dispatcher.newUUID == nil {
		return PreparedMutation{}, fmt.Errorf("gateway logging mutation dispatcher is incomplete")
	}
	if state.Host.Role != model.RoleGateway {
		return PreparedMutation{}, fmt.Errorf("gateway logging mutation requires gateway state")
	}
	memory := &loggingCandidateStore{state: state}
	manager, err := operations.NewLoggingManager(memory, operations.ValidatingLoggingRuntime{}, operations.LoggingManagerOptions{
		Now: dispatcher.now, NewUUID: dispatcher.newUUID,
		FileDirectory: filepath.Join(dispatcher.paths.Root, "var", "log", "vpnctl"),
	})
	if err != nil {
		return PreparedMutation{}, err
	}
	var change operations.LoggingChange
	switch operation {
	case "log.enable":
		var payload gatewayLoggingEnablePayload
		if err := decodeClosedLoggingPayload(raw, &payload); err != nil {
			return PreparedMutation{}, err
		}
		if payload.DurationSeconds <= 0 || payload.DurationSeconds > int64(operations.MaximumLoggingDuration/time.Second) {
			return PreparedMutation{}, fmt.Errorf("gateway logging duration is outside the supported range")
		}
		change, err = manager.Enable(ctx, operations.LoggingEnableRequest{
			Scope: payload.Scope, Level: payload.Level, Duration: time.Duration(payload.DurationSeconds) * time.Second, File: payload.File,
		})
	case "log.disable":
		var payload gatewayLoggingDisablePayload
		if err := decodeClosedLoggingPayload(raw, &payload); err != nil {
			return PreparedMutation{}, err
		}
		change, err = manager.Disable(ctx, payload.Scope)
	default:
		return PreparedMutation{}, fmt.Errorf("unsupported gateway logging mutation operation")
	}
	if err != nil {
		return PreparedMutation{}, err
	}
	data, err := json.Marshal(change)
	if err != nil {
		return PreparedMutation{}, fmt.Errorf("encode logging mutation result: %w", err)
	}
	prepared := PreparedMutation{Candidate: memory.state, Changed: change.Changed, Data: data}
	if change.Changed {
		prepared.Apply = func(context.Context) error { return nil }
		prepared.Rollback = func(context.Context) error { return nil }
	}
	return prepared, nil
}

func decodeClosedLoggingPayload(raw json.RawMessage, destination any) error {
	if len(raw) == 0 || len(raw) > 4096 {
		return fmt.Errorf("gateway logging mutation payload has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode gateway logging mutation payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode gateway logging mutation payload: trailing data")
	}
	return nil
}

type loggingCandidateStore struct {
	state model.State
}

func (store *loggingCandidateStore) Load() (model.State, error) {
	data, err := model.EncodeState(store.state)
	if err != nil {
		return model.State{}, err
	}
	return model.DecodeState(data)
}

func (store *loggingCandidateStore) Save(expected uint64, candidate model.State) error {
	if expected != store.state.Generation {
		return fmt.Errorf("logging candidate generation conflict")
	}
	if err := model.ValidateTransition(store.state, candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}
