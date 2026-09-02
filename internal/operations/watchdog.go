package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const (
	WatchdogTransactionSchemaVersion = 1
	watchdogDirectoryMode            = 0o700
	watchdogFileMode                 = 0o600
	maximumWatchdogTransactionBytes  = 8 << 20
	watchdogSnapshotFile             = "snapshot.json"
	watchdogLockFile                 = "transaction.lock"
	watchdogActivatedFile            = "activated.json"
	watchdogCommittedFile            = "committed.json"
	watchdogRolledBackFile           = "rolled-back.json"
)

var (
	ErrWatchdogTransactionNotFound = errors.New("watchdog transaction not found")
	ErrWatchdogAlreadyCommitted    = errors.New("watchdog transaction is already committed")
	ErrWatchdogAlreadyRolledBack   = errors.New("watchdog transaction is already rolled back")
	watchdogIDPattern              = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type SSHOrigin struct {
	ClientAddress string `json:"client_address"`
	ClientPort    int    `json:"client_port"`
	ServerAddress string `json:"server_address"`
	ServerPort    int    `json:"server_port"`
}

type WatchdogTransaction struct {
	SchemaVersion  int                           `json:"schema_version"`
	ID             string                        `json:"id"`
	PreparedAt     time.Time                     `json:"prepared_at"`
	Deadline       time.Time                     `json:"deadline"`
	AllowedSSHPort int                           `json:"allowed_ssh_port"`
	Origin         *SSHOrigin                    `json:"origin,omitempty"`
	NetworkSHA256  string                        `json:"network_sha256"`
	Network        linuxplatform.NetworkSnapshot `json:"network"`
}

type WatchdogArmInput struct {
	AllowedSSHPort int
	Origin         *linuxplatform.SSHConnection
	NetworkScope   linuxplatform.OwnedNetworkScope
}

type WatchdogNetwork interface {
	Snapshot(context.Context, linuxplatform.OwnedNetworkScope) (linuxplatform.NetworkSnapshot, error)
	Restore(context.Context, linuxplatform.NetworkSnapshot) error
}

type WatchdogSupervisor interface {
	StartTimer(context.Context, string) error
	TriggerRollback(context.Context, string) error
	StopTimer(context.Context, string) error
}

type WatchdogClock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type UUIDGenerator func() (string, error)

type Watchdog struct {
	store      *WatchdogStore
	network    WatchdogNetwork
	supervisor WatchdogSupervisor
	clock      WatchdogClock
	newID      UUIDGenerator
}

func NewWatchdog(paths store.Paths, network WatchdogNetwork, supervisor WatchdogSupervisor) (*Watchdog, error) {
	transactionStore, err := NewWatchdogStore(paths)
	if err != nil {
		return nil, err
	}
	if network == nil || supervisor == nil {
		return nil, fmt.Errorf("watchdog network and supervisor are required")
	}
	return &Watchdog{
		store:      transactionStore,
		network:    network,
		supervisor: supervisor,
		clock:      systemClock{},
		newID:      model.NewUUID,
	}, nil
}

func NewDefaultWatchdog() (*Watchdog, error) {
	return NewWatchdog(store.DefaultPaths(), linuxplatform.NewOSNetworkManager(), NewSystemdWatchdogSupervisor(linuxplatform.OSProbeRunner{}))
}

// Arm persists the complete rollback input before asking systemd to start the
// timer. Callers must not apply any lockout-risk candidate until Arm succeeds.
func (watchdog *Watchdog) Arm(ctx context.Context, input WatchdogArmInput) (WatchdogTransaction, error) {
	if ctx == nil {
		return WatchdogTransaction{}, fmt.Errorf("context is required")
	}
	if watchdog == nil || watchdog.store == nil || watchdog.network == nil || watchdog.supervisor == nil || watchdog.clock == nil || watchdog.newID == nil {
		return WatchdogTransaction{}, fmt.Errorf("watchdog is incomplete")
	}
	if input.AllowedSSHPort < 1 || input.AllowedSSHPort > 65535 {
		return WatchdogTransaction{}, fmt.Errorf("allowed SSH port must be between 1 and 65535")
	}
	if input.Origin != nil && input.Origin.ServerPort != input.AllowedSSHPort {
		return WatchdogTransaction{}, fmt.Errorf("origin SSH server port does not match the allowed listener")
	}

	network, err := watchdog.network.Snapshot(ctx, input.NetworkScope)
	if err != nil {
		return WatchdogTransaction{}, fmt.Errorf("snapshot prior vpnctl network state: %w", err)
	}
	id, err := watchdog.newID()
	if err != nil {
		return WatchdogTransaction{}, fmt.Errorf("generate watchdog transaction ID: %w", err)
	}
	preparedAt := watchdog.clock.Now().UTC()
	transaction := WatchdogTransaction{
		SchemaVersion:  WatchdogTransactionSchemaVersion,
		ID:             id,
		PreparedAt:     preparedAt,
		Deadline:       preparedAt.Add(linuxplatform.WatchdogSeconds * time.Second),
		AllowedSSHPort: input.AllowedSSHPort,
		Origin:         sshOrigin(input.Origin),
		NetworkSHA256:  networkDigest(network),
		Network:        network,
	}
	if err := transaction.Validate(); err != nil {
		return WatchdogTransaction{}, err
	}
	if err := watchdog.store.Create(transaction); err != nil {
		return WatchdogTransaction{}, err
	}
	if err := watchdog.supervisor.StartTimer(ctx, transaction.ID); err != nil {
		return WatchdogTransaction{}, fmt.Errorf("start independent watchdog timer: %w", err)
	}
	return transaction, nil
}

// MarkActivated records the post-activation boundary used by task 5.7. A kill
// before this marker still rolls back; it can never make a transaction
// confirmable accidentally.
func (watchdog *Watchdog) MarkActivated(transactionID string) error {
	if watchdog == nil || watchdog.store == nil || watchdog.clock == nil {
		return fmt.Errorf("watchdog is incomplete")
	}
	return watchdog.store.MarkActivated(transactionID, watchdog.clock.Now().UTC())
}

// RollbackNow asks the independently supervised executable to run and then
// disarms the still-pending timer. If the caller dies between those actions,
// the later timer invocation is a safe no-op after the rollback marker.
func (watchdog *Watchdog) RollbackNow(ctx context.Context, transactionID string) error {
	if watchdog == nil || watchdog.supervisor == nil {
		return fmt.Errorf("watchdog is incomplete")
	}
	if err := watchdog.supervisor.TriggerRollback(ctx, transactionID); err != nil {
		return err
	}
	if err := watchdog.supervisor.StopTimer(ctx, transactionID); err != nil {
		return fmt.Errorf("stop watchdog timer after rollback: %w", err)
	}
	return nil
}

func (transaction WatchdogTransaction) Validate() error {
	issues := make([]string, 0)
	if transaction.SchemaVersion != WatchdogTransactionSchemaVersion {
		issues = append(issues, fmt.Sprintf("schema_version must be %d", WatchdogTransactionSchemaVersion))
	}
	if !watchdogIDPattern.MatchString(transaction.ID) {
		issues = append(issues, "id must be a canonical lower-case UUID")
	}
	if transaction.PreparedAt.IsZero() || transaction.PreparedAt.Location() != time.UTC {
		issues = append(issues, "prepared_at must be a non-zero UTC timestamp")
	}
	if !transaction.Deadline.Equal(transaction.PreparedAt.Add(linuxplatform.WatchdogSeconds * time.Second)) {
		issues = append(issues, fmt.Sprintf("deadline must be exactly %d seconds after prepared_at", linuxplatform.WatchdogSeconds))
	}
	if transaction.AllowedSSHPort < 1 || transaction.AllowedSSHPort > 65535 {
		issues = append(issues, "allowed_ssh_port must be between 1 and 65535")
	}
	if transaction.Origin != nil {
		if transaction.Origin.ClientAddress == "" || transaction.Origin.ServerAddress == "" || transaction.Origin.ClientPort < 1 || transaction.Origin.ClientPort > 65535 || transaction.Origin.ServerPort != transaction.AllowedSSHPort {
			issues = append(issues, "origin SSH identifiers are invalid")
		}
	}
	if err := transaction.Network.Validate(); err != nil {
		issues = append(issues, err.Error())
	}
	if transaction.NetworkSHA256 != networkDigest(transaction.Network) {
		issues = append(issues, "network snapshot checksum mismatch")
	}
	if len(issues) != 0 {
		return fmt.Errorf("invalid watchdog transaction: %s", strings.Join(issues, "; "))
	}
	return nil
}

type SystemdWatchdogSupervisor struct {
	runner linuxplatform.ProbeRunner
}

func NewSystemdWatchdogSupervisor(runner linuxplatform.ProbeRunner) *SystemdWatchdogSupervisor {
	return &SystemdWatchdogSupervisor{runner: runner}
}

func (supervisor *SystemdWatchdogSupervisor) StartTimer(ctx context.Context, transactionID string) error {
	unit, err := linuxplatform.WatchdogTimerInstance(transactionID)
	if err != nil {
		return err
	}
	return supervisor.systemctl(ctx, "start", unit)
}

func (supervisor *SystemdWatchdogSupervisor) TriggerRollback(ctx context.Context, transactionID string) error {
	unit, err := linuxplatform.WatchdogServiceInstance(transactionID)
	if err != nil {
		return err
	}
	return supervisor.systemctl(ctx, "start", unit)
}

func (supervisor *SystemdWatchdogSupervisor) StopTimer(ctx context.Context, transactionID string) error {
	unit, err := linuxplatform.WatchdogTimerInstance(transactionID)
	if err != nil {
		return err
	}
	return supervisor.systemctl(ctx, "stop", unit)
}

func (supervisor *SystemdWatchdogSupervisor) systemctl(ctx context.Context, action, unit string) error {
	if supervisor == nil || supervisor.runner == nil {
		return fmt.Errorf("systemd watchdog supervisor is incomplete")
	}
	result, err := supervisor.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{action, unit}})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(string(result.Stderr))
		if detail == "" {
			detail = fmt.Sprintf("exit code %d", result.ExitCode)
		}
		return fmt.Errorf("systemctl %s %s: %s", action, unit, detail)
	}
	return nil
}

type WatchdogStore struct {
	paths store.Paths
}

func NewWatchdogStore(paths store.Paths) (*WatchdogStore, error) {
	for label, path := range map[string]string{
		"state": paths.StateDir, "operations": paths.OperationsDir, "watchdog": paths.WatchdogDir,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("%s directory must be clean and absolute", label)
		}
	}
	if filepath.Dir(paths.OperationsDir) != paths.StateDir || filepath.Dir(paths.WatchdogDir) != paths.OperationsDir {
		return nil, fmt.Errorf("watchdog store directories must use the system path hierarchy")
	}
	return &WatchdogStore{paths: paths}, nil
}

func (transactionStore *WatchdogStore) Create(transaction WatchdogTransaction) error {
	if transactionStore == nil {
		return fmt.Errorf("watchdog store is nil")
	}
	if err := transaction.Validate(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(transaction, "", "  ")
	if err != nil {
		return fmt.Errorf("encode watchdog transaction: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maximumWatchdogTransactionBytes {
		return fmt.Errorf("watchdog transaction exceeds %d bytes", maximumWatchdogTransactionBytes)
	}
	if err := transactionStore.ensureRoots(); err != nil {
		return err
	}
	directory := transactionStore.transactionDirectory(transaction.ID)
	if err := os.Mkdir(directory, watchdogDirectoryMode); err != nil {
		return fmt.Errorf("create watchdog transaction directory: %w", err)
	}
	if err := syncWatchdogDirectory(transactionStore.paths.WatchdogDir); err != nil {
		return err
	}
	if err := writeWatchdogFile(directory, watchdogSnapshotFile, encoded, true); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(directory, watchdogLockFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, watchdogFileMode)
	if err != nil {
		return fmt.Errorf("create watchdog transaction lock: %w", err)
	}
	if err := lock.Sync(); err != nil {
		_ = lock.Close()
		return fmt.Errorf("sync watchdog transaction lock: %w", err)
	}
	if err := lock.Close(); err != nil {
		return fmt.Errorf("close watchdog transaction lock: %w", err)
	}
	return syncWatchdogDirectory(directory)
}

func (transactionStore *WatchdogStore) Load(transactionID string) (WatchdogTransaction, error) {
	if !watchdogIDPattern.MatchString(transactionID) {
		return WatchdogTransaction{}, fmt.Errorf("invalid watchdog transaction ID")
	}
	directory := transactionStore.transactionDirectory(transactionID)
	if err := validateWatchdogDirectory(directory); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return WatchdogTransaction{}, fmt.Errorf("%w: %s", ErrWatchdogTransactionNotFound, transactionID)
		}
		return WatchdogTransaction{}, err
	}
	data, err := readWatchdogFile(directory, watchdogSnapshotFile, maximumWatchdogTransactionBytes)
	if err != nil {
		return WatchdogTransaction{}, err
	}
	var transaction WatchdogTransaction
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&transaction); err != nil {
		return WatchdogTransaction{}, fmt.Errorf("decode watchdog transaction: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return WatchdogTransaction{}, fmt.Errorf("decode watchdog transaction: trailing JSON document")
		}
		return WatchdogTransaction{}, fmt.Errorf("decode watchdog transaction trailing data: %w", err)
	}
	if transaction.ID != transactionID {
		return WatchdogTransaction{}, fmt.Errorf("watchdog transaction ID/path mismatch")
	}
	if err := transaction.Validate(); err != nil {
		return WatchdogTransaction{}, err
	}
	return transaction, nil
}

func (transactionStore *WatchdogStore) MarkActivated(transactionID string, activatedAt time.Time) error {
	return transactionStore.withLock(transactionID, func(transaction WatchdogTransaction, directory string) error {
		committed, err := watchdogMarkerExists(directory, watchdogCommittedFile)
		if err != nil {
			return err
		}
		if committed {
			return ErrWatchdogAlreadyCommitted
		}
		rolledBack, err := watchdogMarkerExists(directory, watchdogRolledBackFile)
		if err != nil {
			return err
		}
		if rolledBack {
			return ErrWatchdogAlreadyRolledBack
		}
		if activatedAt.Location() != time.UTC || activatedAt.Before(transaction.PreparedAt) || !activatedAt.Before(transaction.Deadline) {
			return fmt.Errorf("activation time is outside the watchdog window")
		}
		data, err := json.Marshal(struct {
			ActivatedAt time.Time `json:"activated_at"`
		}{ActivatedAt: activatedAt})
		if err != nil {
			return err
		}
		return writeWatchdogFile(directory, watchdogActivatedFile, append(data, '\n'), true)
	})
}

func (transactionStore *WatchdogStore) Rollback(ctx context.Context, transactionID string, network WatchdogNetwork, now time.Time) error {
	if network == nil {
		return fmt.Errorf("watchdog rollback network manager is required")
	}
	return transactionStore.withLock(transactionID, func(transaction WatchdogTransaction, directory string) error {
		committed, err := watchdogMarkerExists(directory, watchdogCommittedFile)
		if err != nil {
			return err
		}
		if committed {
			return nil
		}
		rolledBack, err := watchdogMarkerExists(directory, watchdogRolledBackFile)
		if err != nil {
			return err
		}
		if rolledBack {
			return nil
		}
		if err := network.Restore(ctx, transaction.Network); err != nil {
			return fmt.Errorf("restore watchdog network snapshot: %w", err)
		}
		data, err := json.Marshal(struct {
			RolledBackAt time.Time `json:"rolled_back_at"`
		}{RolledBackAt: now.UTC()})
		if err != nil {
			return err
		}
		return writeWatchdogFile(directory, watchdogRolledBackFile, append(data, '\n'), true)
	})
}

func (transactionStore *WatchdogStore) withLock(transactionID string, action func(WatchdogTransaction, string) error) error {
	transaction, err := transactionStore.Load(transactionID)
	if err != nil {
		return err
	}
	directory := transactionStore.transactionDirectory(transactionID)
	lockPath := filepath.Join(directory, watchdogLockFile)
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open watchdog transaction lock: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock watchdog transaction: %w", err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	transaction, err = transactionStore.Load(transactionID)
	if err != nil {
		return err
	}
	return action(transaction, directory)
}

func (transactionStore *WatchdogStore) ensureRoots() error {
	if err := validateWatchdogDirectory(transactionStore.paths.StateDir); err != nil {
		return fmt.Errorf("validate state directory: %w", err)
	}
	for _, directory := range []string{transactionStore.paths.OperationsDir, transactionStore.paths.WatchdogDir} {
		if err := ensureWatchdogDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func (transactionStore *WatchdogStore) transactionDirectory(transactionID string) string {
	return filepath.Join(transactionStore.paths.WatchdogDir, transactionID)
}

func ensureWatchdogDirectory(path string) error {
	if err := os.Mkdir(path, watchdogDirectoryMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create watchdog directory %s: %w", path, err)
	}
	return validateWatchdogDirectory(path)
}

func validateWatchdogDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("watchdog path %s must be a real directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("watchdog directory %s is not root-only", path)
	}
	return nil
}

func writeWatchdogFile(directory, name string, data []byte, exclusive bool) error {
	if filepath.Base(name) != name || name == "." {
		return fmt.Errorf("invalid watchdog filename")
	}
	if err := validateWatchdogDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("create watchdog temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(watchdogFileMode); err != nil {
		return fmt.Errorf("set watchdog file mode: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write watchdog file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync watchdog file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close watchdog file: %w", err)
	}
	target := filepath.Join(directory, name)
	if exclusive {
		// A same-directory hard link is an atomic no-replace publication on
		// every supported filesystem. Unlike lstat+rename it cannot overwrite
		// a one-time marker created concurrently.
		if err := os.Link(temporaryPath, target); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("watchdog file %s already exists", name)
			}
			return fmt.Errorf("activate watchdog file %s: %w", name, err)
		}
		if err := os.Remove(temporaryPath); err != nil {
			return fmt.Errorf("remove linked watchdog temporary file: %w", err)
		}
		keep = true
	} else {
		if err := os.Rename(temporaryPath, target); err != nil {
			return fmt.Errorf("activate watchdog file %s: %w", name, err)
		}
		keep = true
	}
	return syncWatchdogDirectory(directory)
}

func readWatchdogFile(directory, name string, maximum int64) ([]byte, error) {
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect watchdog file %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("watchdog file %s must be a root-only regular file", name)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("watchdog file %s exceeds %d bytes", name, maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open watchdog file %s: %w", name, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read watchdog file %s: %w", name, err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("watchdog file %s exceeds %d bytes", name, maximum)
	}
	return data, nil
}

func watchdogMarkerExists(directory, name string) (bool, error) {
	info, err := os.Lstat(filepath.Join(directory, name))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect watchdog marker %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("watchdog marker %s must be a root-only regular file", name)
	}
	return true, nil
}

func syncWatchdogDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open watchdog directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync watchdog directory: %w", err)
	}
	return nil
}

func sshOrigin(connection *linuxplatform.SSHConnection) *SSHOrigin {
	if connection == nil {
		return nil
	}
	return &SSHOrigin{
		ClientAddress: connection.ClientAddress,
		ClientPort:    connection.ClientPort,
		ServerAddress: connection.ServerAddress,
		ServerPort:    connection.ServerPort,
	}
}

func networkDigest(snapshot linuxplatform.NetworkSnapshot) string {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// RunDefaultWatchdogRollback is the private service-mode entry point used by
// vpnctl-watchdog@.service. It does not contact the controller.
func RunDefaultWatchdogRollback(ctx context.Context, transactionID string) error {
	paths := store.DefaultPaths()
	transactionStore, err := NewWatchdogStore(paths)
	if err != nil {
		return err
	}
	return transactionStore.Rollback(ctx, transactionID, linuxplatform.NewOSNetworkManager(), time.Now())
}
