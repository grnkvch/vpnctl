package model

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	IdempotencyMaxRecords = 1024
	IdempotencyMaxAge     = 30 * 24 * time.Hour
)

var ErrIdempotencyRecordEvicted = errors.New("idempotency record not retained")

// PruneIdempotencyRecords returns a canonical oldest-to-newest history. A
// record exactly 30 days old remains valid; older records are removed. When
// timestamps tie, request ID provides deterministic ordering.
func PruneIdempotencyRecords(records []IdempotencyRecord, now time.Time) ([]IdempotencyRecord, error) {
	if err := validateTime("now", now); err != nil {
		return nil, err
	}
	canonical := append([]IdempotencyRecord(nil), records...)
	seen := make(map[string]struct{}, len(canonical))
	for index, record := range canonical {
		if err := record.Validate(); err != nil {
			return nil, wrap(indexPath("records", index), err)
		}
		if record.RecordedAt.After(now) {
			return nil, invalid(indexPath("records", index)+".recorded_at", "must not be in the future")
		}
		if _, duplicate := seen[record.RequestID]; duplicate {
			return nil, invalid(indexPath("records", index)+".request_id", "duplicates request %s", record.RequestID)
		}
		seen[record.RequestID] = struct{}{}
	}
	sort.Slice(canonical, func(i, j int) bool {
		if !canonical[i].RecordedAt.Equal(canonical[j].RecordedAt) {
			return canonical[i].RecordedAt.Before(canonical[j].RecordedAt)
		}
		return canonical[i].RequestID < canonical[j].RequestID
	})

	cutoff := now.Add(-IdempotencyMaxAge)
	firstRetained := sort.Search(len(canonical), func(index int) bool {
		return !canonical[index].RecordedAt.Before(cutoff)
	})
	canonical = canonical[firstRetained:]
	if len(canonical) > IdempotencyMaxRecords {
		canonical = canonical[len(canonical)-IdempotencyMaxRecords:]
	}
	result := make([]IdempotencyRecord, len(canonical))
	copy(result, canonical)
	return result, nil
}

// StoreIdempotencyResult prunes the node history and either returns a retained
// prior result for replay or adds the supplied result. Callers that cannot find
// a request ID must reconcile resource state; they must not blindly replay it.
func (node Node) StoreIdempotencyResult(record IdempotencyRecord, now time.Time) (Node, IdempotencyRecord, bool, error) {
	if err := record.Validate(); err != nil {
		return Node{}, IdempotencyRecord{}, false, err
	}
	if err := validateTime("now", now); err != nil {
		return Node{}, IdempotencyRecord{}, false, err
	}
	if record.RecordedAt.After(now) {
		return Node{}, IdempotencyRecord{}, false, invalid("recorded_at", "must not be in the future")
	}
	if record.RecordedAt.Before(now.Add(-IdempotencyMaxAge)) {
		return Node{}, IdempotencyRecord{}, false, invalid("recorded_at", "is older than the retention window")
	}

	pruned, err := PruneIdempotencyRecords(node.IdempotencyRecords, now)
	if err != nil {
		return Node{}, IdempotencyRecord{}, false, fmt.Errorf("prune idempotency history: %w", err)
	}
	for _, retained := range pruned {
		if retained.RequestID == record.RequestID {
			node.IdempotencyRecords = pruned
			return node, retained, true, nil
		}
	}

	pruned = append(pruned, record)
	pruned, err = PruneIdempotencyRecords(pruned, now)
	if err != nil {
		return Node{}, IdempotencyRecord{}, false, fmt.Errorf("prune updated idempotency history: %w", err)
	}
	node.IdempotencyRecords = pruned
	return node, record, false, nil
}

func (node Node) FindIdempotencyResult(requestID string, now time.Time) (IdempotencyRecord, error) {
	if err := validateUUID("request_id", requestID); err != nil {
		return IdempotencyRecord{}, err
	}
	retained, err := PruneIdempotencyRecords(node.IdempotencyRecords, now)
	if err != nil {
		return IdempotencyRecord{}, fmt.Errorf("prune idempotency history: %w", err)
	}
	for _, record := range retained {
		if record.RequestID == requestID {
			return record, nil
		}
	}
	return IdempotencyRecord{}, ErrIdempotencyRecordEvicted
}

func (record IdempotencyRecord) Validate() error {
	if err := validateUUID("request_id", record.RequestID); err != nil {
		return err
	}
	if !validOperationType(record.Operation) {
		return invalid("operation", "unsupported value %q", record.Operation)
	}
	if !validResultStatus(record.ResultStatus) {
		return invalid("result_status", "unsupported value %q", record.ResultStatus)
	}
	if err := validateHash("result_hash", record.ResultHash); err != nil {
		return err
	}
	if record.StateGeneration == 0 {
		return invalid("state_generation", "must be positive")
	}
	return validateTime("recorded_at", record.RecordedAt)
}

func validateIdempotencyHistory(records []IdempotencyRecord) error {
	if records == nil {
		return invalid("records", "must be present as a JSON array")
	}
	if len(records) > IdempotencyMaxRecords {
		return invalid("records", "must contain no more than %d entries", IdempotencyMaxRecords)
	}
	seen := make(map[string]struct{}, len(records))
	for index, record := range records {
		if err := record.Validate(); err != nil {
			return wrap(indexPath("records", index), err)
		}
		if index > 0 {
			previous := records[index-1]
			if record.RecordedAt.Before(previous.RecordedAt) ||
				(record.RecordedAt.Equal(previous.RecordedAt) && record.RequestID <= previous.RequestID) {
				return invalid("records", "must be unique and in canonical oldest-to-newest order")
			}
		}
		if _, duplicate := seen[record.RequestID]; duplicate {
			return invalid(indexPath("records", index)+".request_id", "duplicates request %s", record.RequestID)
		}
		seen[record.RequestID] = struct{}{}
	}
	return nil
}

func validOperationType(operation OperationType) bool {
	switch operation {
	case OperationInit, OperationJoin, OperationApply, OperationRepair, OperationRotate, OperationRevoke, OperationDelete, OperationTransportSwitch, OperationHandshakeHost, OperationExposeCreate, OperationExposeRemove, OperationCertificateRotate, OperationTrustRotate, OperationRestore, OperationUpdate, OperationUninstall, OperationPurge:
		return true
	default:
		return false
	}
}

func validResultStatus(status ResultStatus) bool {
	return status == ResultOK || status == ResultPending || status == ResultDegraded || status == ResultFailed
}
