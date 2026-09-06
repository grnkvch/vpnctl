package main

import (
	"testing"
	"time"
)

func TestGatewayStateFixtureIsValid(t *testing.T) {
	initializedAt := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	if err := newGatewayState(initializedAt).Validate(); err != nil {
		t.Fatalf("gateway state fixture is invalid: %v", err)
	}
}
