package operations

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	AppliedMaterialSchemaVersion       = 1
	AppliedMaterialDirectoryMode       = 0o700
	AppliedMaterialBundleMode          = 0o600
	AppliedMaterialMaximumEntries      = 4096
	AppliedMaterialMaximumContentBytes = 16 << 20
	AppliedMaterialMaximumBundleBytes  = 24 << 20
	appliedMaterialTemporaryAttempts   = 32
	appliedMaterialRedactedMarker      = "<vpnctl-applied-material>"
)

var (
	ErrAppliedMaterialInvalid          = errors.New("applied material is invalid")
	ErrAppliedMaterialUnavailable      = errors.New("applied material is unavailable")
	ErrAppliedMaterialConflict         = errors.New("applied material conflicts with the immutable archive")
	ErrAppliedMaterialUnsafe           = errors.New("applied material archive has an unsafe filesystem shape")
	ErrAppliedMaterialOutcomeUncertain = errors.New("applied material publication outcome is uncertain")
	ErrAppliedMaterialSerialization    = errors.New("applied material cannot be serialized")
)

// AppliedMaterialID is derived only from a canonical applied manifest. It is
// safe metadata, but it cannot be used to load arbitrary retired material:
// FileAppliedMaterialArchive.Load accepts the complete manifest instead.
type AppliedMaterialID string

func (id AppliedMaterialID) String() string { return string(id) }

// AppliedMaterialDescriptor is the content-free projection exposed to repair
// planning and tests. Restorable bytes remain behind AppliedMaterialSet.Use.
type AppliedMaterialDescriptor struct {
	Resource      ManagedResourceKey
	Kind          ManagedResourceKind
	Mode          os.FileMode
	RuntimeSHA256 string
	UnitRuntime   *ManagedUnitRuntime
}

type appliedMaterialEntry struct {
	resource      ManagedResourceKey
	kind          ManagedResourceKind
	mode          os.FileMode
	content       []byte
	runtimeSHA256 string
	unitRuntime   *ManagedUnitRuntime
}

// AppliedMaterial is a constructor value. Its byte fields are deliberately
// private, so generic JSON or formatting cannot serialize generated secrets.
type AppliedMaterial struct {
	entry appliedMaterialEntry
}

func (AppliedMaterial) String() string   { return appliedMaterialRedactedMarker }
func (AppliedMaterial) GoString() string { return appliedMaterialRedactedMarker }
func (AppliedMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, appliedMaterialRedactedMarker)
}
func (AppliedMaterial) MarshalJSON() ([]byte, error) { return nil, ErrAppliedMaterialSerialization }
func (AppliedMaterial) MarshalText() ([]byte, error) { return nil, ErrAppliedMaterialSerialization }

// Destroy wipes the constructor-owned copy after NewAppliedMaterialSet has
// cloned it. It is safe to call more than once.
func (material *AppliedMaterial) Destroy() {
	if material == nil {
		return
	}
	clear(material.entry.content)
	material.entry = appliedMaterialEntry{}
}

// AppliedMaterialSet retains exact restorable bytes for one canonical applied
// manifest. Call Destroy as soon as the archive or executor no longer needs it.
type AppliedMaterialSet struct {
	id         AppliedMaterialID
	generation uint64
	entries    []appliedMaterialEntry
	destroyed  bool
}

func (AppliedMaterialSet) String() string   { return appliedMaterialRedactedMarker }
func (AppliedMaterialSet) GoString() string { return appliedMaterialRedactedMarker }
func (AppliedMaterialSet) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, appliedMaterialRedactedMarker)
}
func (AppliedMaterialSet) MarshalJSON() ([]byte, error) { return nil, ErrAppliedMaterialSerialization }
func (AppliedMaterialSet) MarshalText() ([]byte, error) { return nil, ErrAppliedMaterialSerialization }

// FileAppliedMaterialArchive stores immutable, content-addressed bundles in a
// caller-selected absolute directory. Production callers place that directory
// below the root-owned vpnctl state directory; tests use an isolated root.
type FileAppliedMaterialArchive struct {
	directory string
}

type appliedMaterialBundle struct {
	SchemaVersion int                          `json:"schema_version"`
	MaterialID    string                       `json:"material_id"`
	Generation    uint64                       `json:"generation"`
	Entries       []appliedMaterialBundleEntry `json:"entries"`
}

type appliedMaterialBundleEntry struct {
	Resource      ManagedResourceKey  `json:"resource"`
	Kind          ManagedResourceKind `json:"kind"`
	Mode          string              `json:"mode"`
	Content       []byte              `json:"content"`
	RuntimeSHA256 string              `json:"runtime_sha256"`
	UnitRuntime   *ManagedUnitRuntime `json:"unit_runtime,omitempty"`
}

type appliedMaterialBundleEnvelope struct {
	SchemaVersion int             `json:"schema_version"`
	MaterialID    string          `json:"material_id"`
	Generation    uint64          `json:"generation"`
	Entries       json.RawMessage `json:"entries"`
}

func NewAppliedFileMaterial(key ManagedResourceKey, mode os.FileMode, content []byte) (AppliedMaterial, error) {
	if mode != mode.Perm() || len(content) > AppliedMaterialMaximumContentBytes {
		return AppliedMaterial{}, ErrAppliedMaterialInvalid
	}
	entry := appliedMaterialEntry{resource: key, kind: ManagedResourceFile, mode: mode, content: append([]byte(nil), content...)}
	runtimeSHA256, err := appliedMaterialEntryRuntime(&entry)
	if err != nil {
		clear(entry.content)
		return AppliedMaterial{}, err
	}
	entry.runtimeSHA256 = runtimeSHA256
	return AppliedMaterial{entry: entry}, nil
}

func NewAppliedUnitMaterial(key ManagedResourceKey, mode os.FileMode, content []byte, runtime ManagedUnitRuntime) (AppliedMaterial, error) {
	if mode != mode.Perm() || len(content) > AppliedMaterialMaximumContentBytes {
		return AppliedMaterial{}, ErrAppliedMaterialInvalid
	}
	runtimeCopy := runtime
	entry := appliedMaterialEntry{
		resource: key, kind: ManagedResourceUnit, mode: mode, content: append([]byte(nil), content...), unitRuntime: &runtimeCopy,
	}
	runtimeSHA256, err := appliedMaterialEntryRuntime(&entry)
	if err != nil {
		clear(entry.content)
		return AppliedMaterial{}, err
	}
	entry.runtimeSHA256 = runtimeSHA256
	return AppliedMaterial{entry: entry}, nil
}

func NewAppliedMaterialSet(applied ConvergenceManifest, material []AppliedMaterial) (*AppliedMaterialSet, error) {
	id, canonical, err := appliedMaterialIdentity(applied)
	if err != nil {
		return nil, err
	}
	if len(material) > AppliedMaterialMaximumEntries {
		return nil, ErrAppliedMaterialInvalid
	}
	set := &AppliedMaterialSet{id: id, generation: canonical.Generation, entries: make([]appliedMaterialEntry, len(material))}
	for index := range material {
		set.entries[index] = cloneAppliedMaterialEntry(material[index].entry)
	}
	sort.Slice(set.entries, func(left, right int) bool {
		return resourceOrder(set.entries[left].resource) < resourceOrder(set.entries[right].resource)
	})
	if err := set.validate(canonical); err != nil {
		set.Destroy()
		return nil, err
	}
	return set, nil
}

func AppliedMaterialIDFor(applied ConvergenceManifest) (AppliedMaterialID, error) {
	id, _, err := appliedMaterialIdentity(applied)
	return id, err
}

func NewFileAppliedMaterialArchive(directory string) (*FileAppliedMaterialArchive, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Base(directory) == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: archive directory must be clean and absolute", ErrAppliedMaterialInvalid)
	}
	return &FileAppliedMaterialArchive{directory: directory}, nil
}

func (set *AppliedMaterialSet) ID() AppliedMaterialID {
	if set == nil || set.destroyed {
		return ""
	}
	return set.id
}

func (set *AppliedMaterialSet) Generation() uint64 {
	if set == nil || set.destroyed {
		return 0
	}
	return set.generation
}

func (set *AppliedMaterialSet) Descriptors() []AppliedMaterialDescriptor {
	if set == nil || set.destroyed {
		return []AppliedMaterialDescriptor{}
	}
	result := make([]AppliedMaterialDescriptor, len(set.entries))
	for index, entry := range set.entries {
		result[index] = AppliedMaterialDescriptor{
			Resource: entry.resource, Kind: entry.kind, Mode: entry.mode,
			RuntimeSHA256: entry.runtimeSHA256, UnitRuntime: cloneManagedUnitRuntime(entry.unitRuntime),
		}
	}
	return result
}

// Use supplies a disposable copy of one material payload. The copy is wiped
// immediately after use, including when the callback returns an error.
func (set *AppliedMaterialSet) Use(
	resource ManagedResourceKey,
	use func(mode os.FileMode, content []byte, unitRuntime *ManagedUnitRuntime) error,
) error {
	if set == nil || set.destroyed || use == nil {
		return ErrAppliedMaterialInvalid
	}
	order := resourceOrder(resource)
	index := sort.Search(len(set.entries), func(index int) bool { return resourceOrder(set.entries[index].resource) >= order })
	if index == len(set.entries) || set.entries[index].resource != resource {
		return ErrAppliedMaterialInvalid
	}
	content := append([]byte(nil), set.entries[index].content...)
	defer clear(content)
	return use(set.entries[index].mode, content, cloneManagedUnitRuntime(set.entries[index].unitRuntime))
}

func (set *AppliedMaterialSet) Destroy() {
	if set == nil || set.destroyed {
		return
	}
	for index := range set.entries {
		clear(set.entries[index].content)
		set.entries[index] = appliedMaterialEntry{}
	}
	set.entries = nil
	set.id = ""
	set.generation = 0
	set.destroyed = true
}

// Ensure publishes one immutable bundle or accepts an existing byte-identical
// bundle. Existing unequal or unsafe entries are conflicts and are never
// replaced. The returned ID is meaningful on outcome-uncertain errors too.
func (archive *FileAppliedMaterialArchive) Ensure(
	ctx context.Context,
	applied ConvergenceManifest,
	material *AppliedMaterialSet,
) (AppliedMaterialID, error) {
	if ctx == nil || archive == nil || archive.directory == "" || material == nil {
		return "", ErrAppliedMaterialInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	_, canonical, err := appliedMaterialIdentity(applied)
	if err != nil || material.validate(canonical) != nil {
		return "", ErrAppliedMaterialInvalid
	}
	encoded, err := material.encode()
	if err != nil {
		return "", err
	}
	defer clear(encoded)

	directoryFD, err := archive.openDirectory(true)
	if err != nil {
		return "", err
	}
	defer unix.Close(directoryFD)
	if err := lockAppliedMaterialDirectory(ctx, directoryFD, true); err != nil {
		return "", err
	}
	if err := cleanupAppliedMaterialCandidates(directoryFD); err != nil {
		return "", err
	}
	name := appliedMaterialBundleName(material.id)
	equal, present, err := readAndCompareAppliedMaterialBundle(directoryFD, name, encoded)
	if err != nil {
		return "", err
	}
	if present {
		if !equal {
			return "", ErrAppliedMaterialConflict
		}
		return material.id, nil
	}

	temporary, file, err := createAppliedMaterialTemporary(directoryFD)
	if err != nil {
		return "", err
	}
	keepTemporary := true
	defer func() {
		_ = file.Close()
		if keepTemporary {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	if err := writeAppliedMaterial(file, encoded); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync applied material candidate")
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close applied material candidate")
	}
	if err := unix.Linkat(directoryFD, temporary, directoryFD, name, 0); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return "", fmt.Errorf("activate applied material bundle")
		}
		equal, present, compareErr := readAndCompareAppliedMaterialBundle(directoryFD, name, encoded)
		if compareErr != nil {
			return "", compareErr
		}
		if !present || !equal {
			return "", ErrAppliedMaterialConflict
		}
		return material.id, nil
	}
	if err := unix.Unlinkat(directoryFD, temporary, 0); err != nil {
		_ = unix.Fsync(directoryFD)
		return material.id, ErrAppliedMaterialOutcomeUncertain
	}
	keepTemporary = false
	if err := unix.Fsync(directoryFD); err != nil {
		return material.id, ErrAppliedMaterialOutcomeUncertain
	}
	return material.id, nil
}

// Load derives the only legal bundle ID from applied and validates every
// decoded payload against that manifest before returning any content.
func (archive *FileAppliedMaterialArchive) Load(ctx context.Context, applied ConvergenceManifest) (*AppliedMaterialSet, error) {
	if ctx == nil || archive == nil || archive.directory == "" {
		return nil, ErrAppliedMaterialInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id, canonical, err := appliedMaterialIdentity(applied)
	if err != nil {
		return nil, err
	}
	directoryFD, err := archive.openDirectory(false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directoryFD)
	if err := lockAppliedMaterialDirectory(ctx, directoryFD, false); err != nil {
		return nil, err
	}
	encoded, err := readAppliedMaterialBundle(directoryFD, appliedMaterialBundleName(id))
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	set, err := decodeAppliedMaterialSet(encoded, canonical, id)
	if err != nil {
		return nil, ErrAppliedMaterialConflict
	}
	return set, nil
}

// Discard removes one exact, validated bundle. It is intended only for a
// transaction candidate whose convergence publication has been conclusively
// rolled back; callers cannot select material by an arbitrary ID.
func (archive *FileAppliedMaterialArchive) Discard(ctx context.Context, applied ConvergenceManifest) (bool, error) {
	if ctx == nil || archive == nil || archive.directory == "" {
		return false, ErrAppliedMaterialInvalid
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	id, canonical, err := appliedMaterialIdentity(applied)
	if err != nil {
		return false, err
	}
	directoryFD, err := archive.openDirectory(false)
	if err != nil {
		return false, err
	}
	defer unix.Close(directoryFD)
	if err := lockAppliedMaterialDirectory(ctx, directoryFD, true); err != nil {
		return false, err
	}
	if err := cleanupAppliedMaterialCandidates(directoryFD); err != nil {
		return false, err
	}
	name := appliedMaterialBundleName(id)
	encoded, err := readAppliedMaterialBundle(directoryFD, name)
	if errors.Is(err, ErrAppliedMaterialUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer clear(encoded)
	set, err := decodeAppliedMaterialSet(encoded, canonical, id)
	if err != nil {
		return false, ErrAppliedMaterialConflict
	}
	set.Destroy()
	if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
		return false, ErrAppliedMaterialConflict
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return true, ErrAppliedMaterialOutcomeUncertain
	}
	return true, nil
}

func appliedMaterialIdentity(applied ConvergenceManifest) (AppliedMaterialID, ConvergenceManifest, error) {
	if err := applied.Validate(); err != nil {
		return "", ConvergenceManifest{}, fmt.Errorf("%w: applied manifest", ErrAppliedMaterialInvalid)
	}
	canonical, err := NewConvergenceManifest(applied.Generation, applied.Resources)
	if err != nil {
		return "", ConvergenceManifest{}, fmt.Errorf("%w: applied manifest", ErrAppliedMaterialInvalid)
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", ConvergenceManifest{}, fmt.Errorf("%w: encode applied manifest", ErrAppliedMaterialInvalid)
	}
	defer clear(encoded)
	return AppliedMaterialID(ManagedFingerprint(encoded)), canonical, nil
}

func (set *AppliedMaterialSet) validate(applied ConvergenceManifest) error {
	if set == nil || set.destroyed || set.generation != applied.Generation || len(set.entries) != appliedMaterialResourceCount(applied) || len(set.entries) > AppliedMaterialMaximumEntries {
		return ErrAppliedMaterialInvalid
	}
	wantID, canonical, err := appliedMaterialIdentity(applied)
	if err != nil || set.id != wantID {
		return ErrAppliedMaterialInvalid
	}
	expected := make(map[string]ManagedResource, len(canonical.Resources))
	for _, resource := range canonical.Resources {
		if resource.Key.Kind == ManagedResourceFile || resource.Key.Kind == ManagedResourceUnit {
			expected[resourceOrder(resource.Key)] = resource
		}
	}
	total := 0
	previous := ""
	for index := range set.entries {
		entry := &set.entries[index]
		runtimeSHA256, err := appliedMaterialEntryRuntime(entry)
		if err != nil || entry.runtimeSHA256 != runtimeSHA256 {
			return ErrAppliedMaterialInvalid
		}
		order := resourceOrder(entry.resource)
		if index > 0 && order <= previous {
			return ErrAppliedMaterialInvalid
		}
		previous = order
		resource, found := expected[order]
		if !found || resource.Key != entry.resource || resource.Key.Kind != entry.kind || resource.RuntimeSHA256 != entry.runtimeSHA256 {
			return ErrAppliedMaterialInvalid
		}
		delete(expected, order)
		total += len(entry.content)
		if total > AppliedMaterialMaximumContentBytes {
			return ErrAppliedMaterialInvalid
		}
	}
	if len(expected) != 0 {
		return ErrAppliedMaterialInvalid
	}
	return nil
}

func appliedMaterialResourceCount(applied ConvergenceManifest) int {
	count := 0
	for _, resource := range applied.Resources {
		if resource.Key.Kind == ManagedResourceFile || resource.Key.Kind == ManagedResourceUnit {
			count++
		}
	}
	return count
}

func appliedMaterialEntryRuntime(entry *appliedMaterialEntry) (string, error) {
	if entry == nil || entry.resource.validate() != nil || entry.resource.Kind != entry.kind || entry.mode != entry.mode.Perm() || len(entry.content) > AppliedMaterialMaximumContentBytes {
		return "", ErrAppliedMaterialInvalid
	}
	mode := fmt.Sprintf("%04o", entry.mode.Perm())
	contentDigest := sha256.Sum256(entry.content)
	contentSHA256 := hex.EncodeToString(contentDigest[:])
	var runtimeSHA256 string
	var err error
	switch entry.kind {
	case ManagedResourceFile:
		if entry.unitRuntime != nil {
			return "", ErrAppliedMaterialInvalid
		}
		runtimeSHA256, err = managedFileRuntimeFingerprint("regular", mode, contentSHA256)
	case ManagedResourceUnit:
		if entry.unitRuntime == nil || entry.unitRuntime.FileType != "regular" || entry.unitRuntime.Mode != mode || entry.unitRuntime.ContentSHA256 != contentSHA256 {
			return "", ErrAppliedMaterialInvalid
		}
		runtimeSHA256, err = ManagedUnitRuntimeFingerprint(*entry.unitRuntime)
	default:
		return "", ErrAppliedMaterialInvalid
	}
	if err != nil {
		return "", ErrAppliedMaterialInvalid
	}
	return runtimeSHA256, nil
}

func (set *AppliedMaterialSet) encode() ([]byte, error) {
	bundle := appliedMaterialBundle{
		SchemaVersion: AppliedMaterialSchemaVersion, MaterialID: set.id.String(), Generation: set.generation,
		Entries: make([]appliedMaterialBundleEntry, len(set.entries)),
	}
	for index, entry := range set.entries {
		bundle.Entries[index] = appliedMaterialBundleEntry{
			Resource: entry.resource, Kind: entry.kind, Mode: fmt.Sprintf("%04o", entry.mode.Perm()),
			Content: append([]byte(nil), entry.content...), RuntimeSHA256: entry.runtimeSHA256,
			UnitRuntime: cloneManagedUnitRuntime(entry.unitRuntime),
		}
	}
	encoded, err := json.Marshal(bundle)
	for index := range bundle.Entries {
		clear(bundle.Entries[index].Content)
	}
	if err != nil || len(encoded) > AppliedMaterialMaximumBundleBytes {
		clear(encoded)
		return nil, ErrAppliedMaterialInvalid
	}
	encoded = append(encoded, '\n')
	if len(encoded) > AppliedMaterialMaximumBundleBytes {
		clear(encoded)
		return nil, ErrAppliedMaterialInvalid
	}
	return encoded, nil
}

func decodeAppliedMaterialSet(encoded []byte, applied ConvergenceManifest, id AppliedMaterialID) (*AppliedMaterialSet, error) {
	if len(encoded) == 0 || len(encoded) > AppliedMaterialMaximumBundleBytes {
		return nil, ErrAppliedMaterialInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var envelope appliedMaterialBundleEnvelope
	defer func() { clear(envelope.Entries) }()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, ErrAppliedMaterialInvalid
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		clear(trailing)
		return nil, ErrAppliedMaterialInvalid
	}
	entries, err := decodeAppliedMaterialBundleEntries(envelope.Entries)
	if err != nil {
		return nil, err
	}
	bundle := appliedMaterialBundle{
		SchemaVersion: envelope.SchemaVersion,
		MaterialID:    envelope.MaterialID,
		Generation:    envelope.Generation,
		Entries:       entries,
	}
	defer clearAppliedMaterialBundle(&bundle)
	if bundle.SchemaVersion != AppliedMaterialSchemaVersion || bundle.MaterialID != id.String() || bundle.Generation != applied.Generation {
		return nil, ErrAppliedMaterialInvalid
	}
	set := &AppliedMaterialSet{id: id, generation: bundle.Generation, entries: make([]appliedMaterialEntry, len(bundle.Entries))}
	for index, entry := range bundle.Entries {
		mode, err := strconv.ParseUint(entry.Mode, 8, 32)
		if err != nil || len(entry.Mode) != 4 || entry.Mode[0] != '0' || fmt.Sprintf("%04o", mode) != entry.Mode {
			set.Destroy()
			return nil, ErrAppliedMaterialInvalid
		}
		set.entries[index] = appliedMaterialEntry{
			resource: entry.Resource, kind: entry.Kind, mode: os.FileMode(mode), content: append([]byte(nil), entry.Content...),
			runtimeSHA256: entry.RuntimeSHA256, unitRuntime: cloneManagedUnitRuntime(entry.UnitRuntime),
		}
	}
	if err := set.validate(applied); err != nil {
		set.Destroy()
		return nil, err
	}
	return set, nil
}

func decodeAppliedMaterialBundleEntries(encoded json.RawMessage) ([]appliedMaterialBundleEntry, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	delimiter, valid := token.(json.Delim)
	if err != nil || !valid || delimiter != '[' {
		return nil, ErrAppliedMaterialInvalid
	}
	entries := make([]appliedMaterialBundleEntry, 0)
	for decoder.More() {
		if len(entries) == AppliedMaterialMaximumEntries {
			clearAppliedMaterialBundleEntries(entries)
			return nil, ErrAppliedMaterialInvalid
		}
		var entry appliedMaterialBundleEntry
		if err := decoder.Decode(&entry); err != nil {
			clear(entry.Content)
			clearAppliedMaterialBundleEntries(entries)
			return nil, ErrAppliedMaterialInvalid
		}
		entries = append(entries, entry)
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
		clearAppliedMaterialBundleEntries(entries)
		return nil, ErrAppliedMaterialInvalid
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		clear(trailing)
		clearAppliedMaterialBundleEntries(entries)
		return nil, ErrAppliedMaterialInvalid
	}
	return entries, nil
}

func (archive *FileAppliedMaterialArchive) openDirectory(create bool) (int, error) {
	parent := filepath.Dir(archive.directory)
	name := filepath.Base(archive.directory)
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if !create && errors.Is(err, unix.ENOENT) {
			return -1, ErrAppliedMaterialUnavailable
		}
		return -1, fmt.Errorf("%w: open archive parent", ErrAppliedMaterialUnsafe)
	}
	defer unix.Close(parentFD)
	if err := requireAppliedMaterialFD(parentFD, unix.S_IFDIR, AppliedMaterialDirectoryMode); err != nil {
		return -1, err
	}
	created := false
	if create {
		if err := unix.Mkdirat(parentFD, name, AppliedMaterialDirectoryMode); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return -1, fmt.Errorf("create applied material archive")
			}
		} else {
			created = true
		}
	}
	directoryFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if !create && errors.Is(err, unix.ENOENT) {
			return -1, ErrAppliedMaterialUnavailable
		}
		return -1, errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
	}
	if created {
		if err := unix.Fchmod(directoryFD, AppliedMaterialDirectoryMode); err != nil {
			_ = unix.Close(directoryFD)
			return -1, fmt.Errorf("restrict applied material archive")
		}
	}
	if err := requireAppliedMaterialFD(directoryFD, unix.S_IFDIR, AppliedMaterialDirectoryMode); err != nil {
		_ = unix.Close(directoryFD)
		return -1, err
	}
	if created {
		if err := unix.Fsync(parentFD); err != nil {
			_ = unix.Close(directoryFD)
			return -1, fmt.Errorf("sync applied material archive parent")
		}
	}
	return directoryFD, nil
}

func requireAppliedMaterialFD(fd int, fileType uint32, mode os.FileMode) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
	}
	if uint32(stat.Mode)&unix.S_IFMT != fileType || os.FileMode(stat.Mode).Perm() != mode || stat.Uid != uint32(os.Geteuid()) {
		return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
	}
	if fileType == unix.S_IFREG && stat.Nlink != 1 {
		return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
	}
	return nil
}

func lockAppliedMaterialDirectory(ctx context.Context, directoryFD int, exclusive bool) error {
	operation := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		operation = unix.LOCK_EX | unix.LOCK_NB
	}
	for {
		if err := unix.Flock(directoryFD, operation); err == nil {
			return nil
		} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return fmt.Errorf("lock applied material archive")
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// cleanupAppliedMaterialCandidates runs only under the archive's exclusive
// directory lock. A candidate can therefore only be crash residue from a
// cooperating writer. Removing the directory entry is safe even when the
// crash happened after linkat: the published bundle retains its other link.
func cleanupAppliedMaterialCandidates(directoryFD int) error {
	listingFD, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
	}
	listing := os.NewFile(uintptr(listingFD), "vpnctl-applied-material-directory")
	if listing == nil {
		_ = unix.Close(listingFD)
		return ErrAppliedMaterialUnsafe
	}
	entries, err := listing.ReadDir(-1)
	_ = listing.Close()
	if err != nil {
		return ErrAppliedMaterialUnsafe
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".candidate-") {
			continue
		}
		if !validAppliedMaterialCandidateName(name) {
			return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
		}
		fd, openErr := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(fd, &stat)
		_ = unix.Close(fd)
		if statErr != nil || uint32(stat.Mode)&unix.S_IFMT != unix.S_IFREG || os.FileMode(stat.Mode).Perm() != AppliedMaterialBundleMode || stat.Uid != uint32(os.Geteuid()) || stat.Nlink < 1 || stat.Nlink > 2 {
			return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
		}
		if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
			return errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
		}
		removed = true
	}
	if removed {
		if err := unix.Fsync(directoryFD); err != nil {
			return ErrAppliedMaterialOutcomeUncertain
		}
	}
	return nil
}

func validAppliedMaterialCandidateName(name string) bool {
	const prefix = ".candidate-"
	if len(name) != len(prefix)+24 || !strings.HasPrefix(name, prefix) {
		return false
	}
	for _, character := range name[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func readAndCompareAppliedMaterialBundle(directoryFD int, name string, want []byte) (bool, bool, error) {
	got, err := readAppliedMaterialBundle(directoryFD, name)
	if errors.Is(err, ErrAppliedMaterialUnavailable) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer clear(got)
	return bytes.Equal(got, want), true, nil
}

func readAppliedMaterialBundle(directoryFD int, name string) ([]byte, error) {
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, ErrAppliedMaterialUnavailable
		}
		return nil, errors.Join(ErrAppliedMaterialConflict, ErrAppliedMaterialUnsafe)
	}
	file := os.NewFile(uintptr(fd), "vpnctl-applied-material")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrAppliedMaterialUnavailable
	}
	defer file.Close()
	if err := requireAppliedMaterialFD(fd, unix.S_IFREG, AppliedMaterialBundleMode); err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Size < 1 || stat.Size > AppliedMaterialMaximumBundleBytes {
		return nil, ErrAppliedMaterialConflict
	}
	data, err := io.ReadAll(io.LimitReader(file, AppliedMaterialMaximumBundleBytes+1))
	if err != nil || len(data) < 1 || len(data) > AppliedMaterialMaximumBundleBytes || int64(len(data)) != stat.Size {
		clear(data)
		return nil, ErrAppliedMaterialConflict
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameAppliedMaterialFile(stat, after) {
		clear(data)
		return nil, ErrAppliedMaterialConflict
	}
	return data, nil
}

func sameAppliedMaterialFile(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode && before.Nlink == after.Nlink &&
		before.Uid == after.Uid && before.Gid == after.Gid && before.Size == after.Size
}

func createAppliedMaterialTemporary(directoryFD int) (string, *os.File, error) {
	for attempt := 0; attempt < appliedMaterialTemporaryAttempts; attempt++ {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return "", nil, fmt.Errorf("create applied material candidate name")
		}
		name := ".candidate-" + hex.EncodeToString(random)
		fd, err := unix.Openat(directoryFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, AppliedMaterialBundleMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, fmt.Errorf("create applied material candidate")
		}
		if err := unix.Fchmod(fd, AppliedMaterialBundleMode); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(directoryFD, name, 0)
			return "", nil, fmt.Errorf("restrict applied material candidate")
		}
		file := os.NewFile(uintptr(fd), "vpnctl-applied-material-candidate")
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(directoryFD, name, 0)
			return "", nil, fmt.Errorf("wrap applied material candidate")
		}
		return name, file, nil
	}
	return "", nil, fmt.Errorf("create applied material candidate")
}

func writeAppliedMaterial(file *os.File, content []byte) error {
	for len(content) != 0 {
		written, err := file.Write(content)
		if err != nil {
			return fmt.Errorf("write applied material candidate")
		}
		if written <= 0 {
			return fmt.Errorf("write applied material candidate")
		}
		content = content[written:]
	}
	return nil
}

func appliedMaterialBundleName(id AppliedMaterialID) string { return id.String() + ".bundle" }

func cloneAppliedMaterialEntry(entry appliedMaterialEntry) appliedMaterialEntry {
	return appliedMaterialEntry{
		resource: entry.resource, kind: entry.kind, mode: entry.mode, content: append([]byte(nil), entry.content...),
		runtimeSHA256: entry.runtimeSHA256, unitRuntime: cloneManagedUnitRuntime(entry.unitRuntime),
	}
}

func cloneManagedUnitRuntime(runtime *ManagedUnitRuntime) *ManagedUnitRuntime {
	if runtime == nil {
		return nil
	}
	copy := *runtime
	return &copy
}

func clearAppliedMaterialBundle(bundle *appliedMaterialBundle) {
	if bundle == nil {
		return
	}
	clearAppliedMaterialBundleEntries(bundle.Entries)
	*bundle = appliedMaterialBundle{}
}

func clearAppliedMaterialBundleEntries(entries []appliedMaterialBundleEntry) {
	for index := range entries {
		clear(entries[index].Content)
		entries[index] = appliedMaterialBundleEntry{}
	}
}
