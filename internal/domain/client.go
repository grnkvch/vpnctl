package domain

import "time"

type ClientStatus string

const (
	ClientStatusActive  ClientStatus = "active"
	ClientStatusRevoked ClientStatus = "revoked"
	ClientStatusDeleted ClientStatus = "deleted"
)

type Client struct {
	ID              string
	Name            string
	Platform        string
	Status          ClientStatus
	AssignedIP      string
	PublicKey       string
	PrivateKeyRef   string
	PresharedKeyRef string
	CreatedAt       time.Time
	RevokedAt       *time.Time
	Tags            []string
}
