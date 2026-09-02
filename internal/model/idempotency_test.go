package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestPruneIdempotencyRecordsAppliesAgeBound(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	exactlyAtCutoff := resultRecord(1, now.Add(-IdempotencyMaxAge))
	expired := resultRecord(2, now.Add(-IdempotencyMaxAge-time.Nanosecond))
	recent := resultRecord(3, now.Add(-time.Hour))
	retained, err := PruneIdempotencyRecords([]IdempotencyRecord{recent, expired, exactlyAtCutoff}, now)
	if err != nil {
		t.Fatalf("PruneIdempotencyRecords() error = %v", err)
	}
	want := []IdempotencyRecord{exactlyAtCutoff, recent}
	if !reflect.DeepEqual(retained, want) {
		t.Fatalf("retained records = %#v, want %#v", retained, want)
	}
}

func TestPruneIdempotencyRecordsAppliesCountBound(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	records := make([]IdempotencyRecord, IdempotencyMaxRecords+76)
	for index := range records {
		records[index] = resultRecord(uint64(index+1), now.Add(-time.Duration(len(records)-index)*time.Second))
	}
	// Deliberately scramble the input; pruning also owns canonical ordering.
	sort.Slice(records, func(i, j int) bool { return records[i].RequestID > records[j].RequestID })
	retained, err := PruneIdempotencyRecords(records, now)
	if err != nil {
		t.Fatalf("PruneIdempotencyRecords() error = %v", err)
	}
	if len(retained) != IdempotencyMaxRecords {
		t.Fatalf("retained count = %d, want %d", len(retained), IdempotencyMaxRecords)
	}
	if got, want := retained[0].RequestID, testUUID(77); got != want {
		t.Fatalf("oldest retained request = %q, want %q", got, want)
	}
	if got, want := retained[len(retained)-1].RequestID, testUUID(uint64(len(records))); got != want {
		t.Fatalf("newest retained request = %q, want %q", got, want)
	}
}

func TestStoreIdempotencyResultReplaysPriorResult(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	node := gatewayState().Nodes[0]
	original := resultRecord(1, now.Add(-time.Minute))
	updated, stored, replayed, err := node.StoreIdempotencyResult(original, now)
	if err != nil || replayed || stored != original || len(updated.IdempotencyRecords) != 1 {
		t.Fatalf("initial StoreIdempotencyResult() = %#v, %#v, %t, %v", updated, stored, replayed, err)
	}

	conflictingRetry := original
	conflictingRetry.Operation = OperationDelete
	conflictingRetry.ResultStatus = ResultFailed
	conflictingRetry.ResultHash = digest("8")
	conflictingRetry.StateGeneration++
	conflictingRetry.RecordedAt = now
	retried, stored, replayed, err := updated.StoreIdempotencyResult(conflictingRetry, now)
	if err != nil || !replayed {
		t.Fatalf("retry StoreIdempotencyResult() replayed = %t, error = %v", replayed, err)
	}
	if stored != original || !reflect.DeepEqual(retried.IdempotencyRecords, []IdempotencyRecord{original}) {
		t.Fatalf("retry did not preserve stored result: stored=%#v history=%#v", stored, retried.IdempotencyRecords)
	}

	found, err := retried.FindIdempotencyResult(original.RequestID, now)
	if err != nil || found != original {
		t.Fatalf("FindIdempotencyResult() = %#v, %v", found, err)
	}
	if _, err := retried.FindIdempotencyResult(testUUID(99), now); !errors.Is(err, ErrIdempotencyRecordEvicted) {
		t.Fatalf("unknown FindIdempotencyResult() error = %v", err)
	}
	if _, err := retried.FindIdempotencyResult(original.RequestID, original.RecordedAt.Add(IdempotencyMaxAge)); err != nil {
		t.Fatalf("exact-cutoff FindIdempotencyResult() error = %v", err)
	}
	if _, err := retried.FindIdempotencyResult(original.RequestID, original.RecordedAt.Add(IdempotencyMaxAge+time.Nanosecond)); !errors.Is(err, ErrIdempotencyRecordEvicted) {
		t.Fatalf("expired FindIdempotencyResult() error = %v", err)
	}
}

func TestIdempotencyHistoryRejectsInvalidData(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		records []IdempotencyRecord
	}{
		{name: "duplicate request", records: []IdempotencyRecord{resultRecord(1, now), resultRecord(1, now)}},
		{name: "future", records: []IdempotencyRecord{resultRecord(1, now.Add(time.Nanosecond))}},
		{name: "bad hash", records: []IdempotencyRecord{func() IdempotencyRecord { record := resultRecord(1, now); record.ResultHash = "secret"; return record }()}},
		{name: "bad status", records: []IdempotencyRecord{func() IdempotencyRecord {
			record := resultRecord(1, now)
			record.ResultStatus = "validation"
			return record
		}()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PruneIdempotencyRecords(test.records, now); err == nil {
				t.Fatal("PruneIdempotencyRecords() accepted invalid records")
			}
		})
	}
}

func TestPersistedIdempotencyRecordIsRedactedMetadata(t *testing.T) {
	t.Parallel()

	state := gatewayState()
	state.Nodes[0].IdempotencyRecords = []IdempotencyRecord{resultRecord(1, state.Nodes[0].CreatedAt.Add(time.Minute))}
	encoded, err := EncodeState(state)
	if err != nil {
		t.Fatalf("EncodeState() error = %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("decode state JSON: %v", err)
	}
	nodes := document["nodes"].([]any)
	records := nodes[0].(map[string]any)["idempotency_records"].([]any)
	record := records[0].(map[string]any)
	recordJSON, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("encode persisted idempotency record: %v", err)
	}
	for _, forbidden := range []string{
		"request_body", "response_body", "authorization", "private_key", "secret", "token",
		"/telegram/webhook-sensitive", "body-canary", "credential-canary",
	} {
		if bytes.Contains(bytes.ToLower(recordJSON), []byte(forbidden)) {
			t.Errorf("persisted idempotency record contains forbidden data %q", forbidden)
		}
	}
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := []string{"operation_type", "recorded_at", "request_id", "result_hash", "result_status", "state_generation"}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("persisted idempotency keys = %v, want %v", keys, wantKeys)
	}

	withBody := bytes.Replace(encoded, []byte(`"result_status": "ok",`), []byte(`"result_status": "ok", "request_body": "body-canary",`), 1)
	if _, err := DecodeState(withBody); err == nil {
		t.Fatal("DecodeState() accepted an idempotency request body")
	}
}

func TestStateRejectsNonCanonicalOrOversizedIdempotencyHistory(t *testing.T) {
	t.Parallel()

	state := gatewayState()
	first := resultRecord(1, state.Nodes[0].CreatedAt.Add(time.Minute))
	second := resultRecord(2, state.Nodes[0].CreatedAt.Add(2*time.Minute))
	state.Nodes[0].IdempotencyRecords = []IdempotencyRecord{second, first}
	if err := state.Validate(); err == nil {
		t.Fatal("State.Validate() accepted non-canonical idempotency history")
	}

	state = gatewayState()
	state.Nodes[0].IdempotencyRecords = make([]IdempotencyRecord, IdempotencyMaxRecords+1)
	for index := range state.Nodes[0].IdempotencyRecords {
		state.Nodes[0].IdempotencyRecords[index] = resultRecord(uint64(index+1), state.Nodes[0].CreatedAt.Add(time.Duration(index+1)*time.Second))
	}
	if err := state.Validate(); err == nil {
		t.Fatal("State.Validate() accepted oversized idempotency history")
	}
}

func TestIdempotencyResultsAreImmutableAcrossStateTransition(t *testing.T) {
	t.Parallel()

	before := gatewayState()
	before.Nodes[0].IdempotencyRecords = []IdempotencyRecord{resultRecord(1, before.Nodes[0].CreatedAt.Add(time.Minute))}
	after := cloneState(t, before)
	after.Generation++
	after.Nodes[0].IdempotencyRecords[0].ResultHash = digest("8")
	if err := ValidateTransition(before, after); err == nil {
		t.Fatal("ValidateTransition() accepted changed stored result")
	}

	after = cloneState(t, before)
	after.Generation++
	after.Nodes[0].IdempotencyRecords = append(after.Nodes[0].IdempotencyRecords, resultRecord(2, before.Nodes[0].CreatedAt.Add(2*time.Minute)))
	if err := ValidateTransition(before, after); err != nil {
		t.Fatalf("ValidateTransition() rejected appended result: %v", err)
	}
}

func resultRecord(sequence uint64, recordedAt time.Time) IdempotencyRecord {
	return IdempotencyRecord{
		RequestID:       testUUID(sequence),
		Operation:       OperationApply,
		ResultStatus:    ResultOK,
		ResultHash:      fmt.Sprintf("%064x", sequence),
		StateGeneration: 7,
		RecordedAt:      recordedAt,
	}
}
