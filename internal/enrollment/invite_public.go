package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

// AuthorizedEnrollmentBuilder prepares the node-specific artifacts after the
// one-time invite has been authenticated but before it is consumed. Task 9.4
// supplies the cross-host join implementation behind this boundary.
type AuthorizedEnrollmentBuilder interface {
	PrepareAuthorizedEnrollment(context.Context, InviteAuthorization, PublicEnrollmentRequest) (PreparedEnrollmentArtifacts, error)
}

type PreparedEnrollmentArtifacts struct {
	NodeID           string
	Transport        model.TransportKind
	Presets          []string
	PublicKeyHashes  map[string][sha256.Size]byte
	AssignmentSHA256 [sha256.Size]byte
	ResponseData     *output.Secret
	Committer        PreparedEnrollmentCommitter
}

// PreparedEnrollmentCommitter owns any staged join resources and must consume
// the invite in the same gateway-state transition that publishes them.
// Builders that do not add resources may leave it nil and use invite-only
// consumption, preserving the generic public enrollment boundary.
type PreparedEnrollmentCommitter interface {
	Commit(context.Context, string) error
	Destroy()
}

type InviteEnrollmentCoordinator struct {
	invites *InviteManager
	builder AuthorizedEnrollmentBuilder
}

func NewInviteEnrollmentCoordinator(invites *InviteManager, builder AuthorizedEnrollmentBuilder) (*InviteEnrollmentCoordinator, error) {
	if invites == nil || builder == nil {
		return nil, fmt.Errorf("invite manager and authorized enrollment builder are required")
	}
	return &InviteEnrollmentCoordinator{invites: invites, builder: builder}, nil
}

func (coordinator *InviteEnrollmentCoordinator) PreparePublicEnrollment(
	ctx context.Context,
	request PublicEnrollmentRequest,
) (PublicEnrollmentTransaction, error) {
	if coordinator == nil || coordinator.invites == nil || coordinator.builder == nil || ctx == nil {
		return nil, ErrPublicEnrollmentUnavailable
	}
	if request.Purpose != PurposeEnroll || request.Endpoint == "" {
		return nil, ErrPublicEnrollmentRejected
	}
	var authorization InviteAuthorization
	if err := request.UseToken(func(token []byte) error {
		var err error
		authorization, err = coordinator.invites.AuthorizeInvite(token)
		return err
	}); err != nil {
		return nil, fmt.Errorf("%w: authorize invite", ErrPublicEnrollmentRejected)
	}
	if authorization.GatewayEndpoint != request.Endpoint {
		return nil, ErrPublicEnrollmentRejected
	}
	artifacts, err := coordinator.builder.PrepareAuthorizedEnrollment(ctx, authorization, request)
	if err != nil {
		return nil, err
	}
	if artifacts.ResponseData == nil {
		if artifacts.Committer != nil {
			artifacts.Committer.Destroy()
		}
		return nil, ErrPublicEnrollmentUnavailable
	}
	transcript, err := NewEnrollmentTranscript(
		PurposeEnroll, authorization.InviteID, authorization.GatewayEndpoint, artifacts.NodeID,
		authorization.IssuedAt, authorization.ExpiresAt, request.NodeNonce, request.GatewayNonce,
		artifacts.Transport, artifacts.Presets, artifacts.PublicKeyHashes, artifacts.AssignmentSHA256,
	)
	if err != nil {
		artifacts.ResponseData.Destroy()
		if artifacts.Committer != nil {
			artifacts.Committer.Destroy()
		}
		return nil, ErrPublicEnrollmentUnavailable
	}
	return &inviteEnrollmentTransaction{
		invites: coordinator.invites, authorization: authorization, transcript: transcript,
		fingerprint: authorization.EnrollmentFingerprint, responseData: artifacts.ResponseData,
		committer: artifacts.Committer,
	}, nil
}

type inviteEnrollmentTransaction struct {
	mu            sync.Mutex
	invites       *InviteManager
	authorization InviteAuthorization
	transcript    EnrollmentTranscript
	fingerprint   string
	responseData  *output.Secret
	committer     PreparedEnrollmentCommitter
	committed     bool
	destroyed     bool
}

func (transaction *inviteEnrollmentTransaction) Transcript() EnrollmentTranscript {
	if transaction == nil {
		return EnrollmentTranscript{}
	}
	return transaction.transcript
}

func (transaction *inviteEnrollmentTransaction) EnrollmentFingerprint() string {
	if transaction == nil {
		return ""
	}
	return transaction.fingerprint
}

func (transaction *inviteEnrollmentTransaction) UseResponseData(callback func(json.RawMessage) error) error {
	if transaction == nil || callback == nil {
		return ErrPublicEnrollmentUnavailable
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.destroyed || transaction.responseData == nil {
		return ErrPublicEnrollmentUnavailable
	}
	return transaction.responseData.Use(func(data []byte) error {
		return callback(json.RawMessage(data))
	})
}

func (transaction *inviteEnrollmentTransaction) Commit(ctx context.Context, replayHash string) error {
	if transaction == nil || ctx == nil {
		return ErrPublicEnrollmentUnavailable
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.destroyed || transaction.committed || transaction.invites == nil {
		return ErrPublicEnrollmentRejected
	}
	var err error
	if transaction.committer != nil {
		err = transaction.committer.Commit(ctx, replayHash)
	} else {
		_, err = transaction.invites.CommitAuthorized(ctx, transaction.authorization, replayHash)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPublicEnrollmentRejected, err)
	}
	transaction.committed = true
	return nil
}

func (transaction *inviteEnrollmentTransaction) Destroy() {
	if transaction == nil {
		return
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.destroyed {
		return
	}
	if transaction.responseData != nil {
		transaction.responseData.Destroy()
	}
	if transaction.committer != nil {
		transaction.committer.Destroy()
	}
	transaction.responseData = nil
	transaction.committer = nil
	transaction.destroyed = true
}
