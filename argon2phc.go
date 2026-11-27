// Package argon2phc hashes and checks passwords with argon2id, stored in the
// PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<digest>
//
// Each hash takes its parameters' memory (64 MiB by default), so a Hasher
// admits hashes against a memory budget: a flood of sign-ins waits, and gives
// up with ErrBusy, instead of exhausting memory. Matches reads the parameters
// from the stored hash, so hashes made with older parameters still check,
// within the Hasher's verification limits, and NeedsRehash says when to
// replace one.
//
// Password policy, such as a minimum length, is the caller's; this package
// only refuses passwords longer than MaximumLength, which bounds the work one
// request can ask for. A hash that has started cannot be interrupted.
package argon2phc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/semaphore"
)

// MaximumLength is the longest password accepted, in bytes.
const MaximumLength = 1024

// Bounds on salts, digests, and encoded hashes, checked before anything is
// decoded or allocated.
const (
	minimumSaltBytes   = 8
	maximumSaltBytes   = 64
	minimumDigestBytes = 16
	maximumDigestBytes = 64
	maximumEncodedSize = 256
)

// Defaults of a Hasher whose arguments leave them zero.
const (
	// DefaultWait is how long a hash waits for memory before ErrBusy.
	DefaultWait = 10 * time.Second
	// DefaultMaximumMemoryKiB is the most memory a stored hash may ask
	// for, 256 MiB: four times the default parameters.
	DefaultMaximumMemoryKiB = 256 * 1024
	// DefaultMaximumPasses is the most passes a stored hash may ask for.
	DefaultMaximumPasses = 16
)

var (
	// ErrTooLong refuses a password longer than MaximumLength.
	ErrTooLong = fmt.Errorf("password longer than %d bytes", MaximumLength)
	// ErrEncoding means a stored hash is not an argon2id PHC string this
	// package can check, or asks for more than the Hasher allows.
	ErrEncoding = errors.New("unreadable password hash")
	// ErrBusy means the hash waited its whole wait for memory.
	ErrBusy = errors.New("too many password hashes at once")
)

// Parameters are the argon2id costs and sizes of a new hash.
type Parameters struct {
	// MemoryKiB is the memory one hash uses, in KiB.
	MemoryKiB uint32
	// Passes is the number of passes over the memory.
	Passes uint32
	// Lanes is the degree of parallelism.
	Lanes uint8
	// SaltBytes is the length of the random salt, 8 to 64.
	SaltBytes uint32
	// DigestBytes is the length of the derived digest, 16 to 64.
	DigestBytes uint32
}

// DefaultParameters returns the OWASP baseline: 64 MiB, three passes, two
// lanes, a 16-byte salt, and a 32-byte digest.
func DefaultParameters() Parameters {
	return Parameters{
		MemoryKiB:   64 * 1024,
		Passes:      3,
		Lanes:       2,
		SaltBytes:   16,
		DigestBytes: 32,
	}
}

// NewHasherArgs configures NewHasher. The zero value is valid.
type NewHasherArgs struct {
	// Parameters are the costs of new hashes. The zero value uses
	// DefaultParameters.
	Parameters Parameters
	// ConcurrentHashes is how many hashes with Parameters may run at once;
	// the memory budget is that many times Parameters.MemoryKiB, and at
	// least MaximumMemoryKiB. Zero or negative uses GOMAXPROCS, at most 4: a
	// container may have many processors and little memory.
	ConcurrentHashes int
	// MaximumMemoryKiB is the most memory, in KiB, a stored hash may ask
	// for in Matches. Zero uses DefaultMaximumMemoryKiB, or
	// Parameters.MemoryKiB when that is larger.
	MaximumMemoryKiB uint32
	// MaximumPasses is the most passes a stored hash may ask for in
	// Matches. Zero uses DefaultMaximumPasses, or Parameters.Passes when
	// that is larger.
	MaximumPasses uint32
	// Wait is how long a hash waits for memory before ErrBusy. Zero or
	// negative uses DefaultWait.
	Wait time.Duration
}

// Hasher hashes and checks passwords within a memory budget. It is safe for
// concurrent use; share one, since each Hasher has its own budget.
type Hasher struct {
	parameters       Parameters
	maximumMemoryKiB uint32
	maximumPasses    uint32
	memory           *semaphore.Weighted
	wait             time.Duration
}

// NewHasher returns a Hasher configured by args, which may be nil.
func NewHasher(args *NewHasherArgs) (*Hasher, error) {
	if args == nil {
		args = &NewHasherArgs{}
	}
	parameters := args.Parameters
	if parameters == (Parameters{}) {
		parameters = DefaultParameters()
	}
	maximumMemoryKiB := max(args.MaximumMemoryKiB, parameters.MemoryKiB)
	if args.MaximumMemoryKiB == 0 {
		maximumMemoryKiB = max(DefaultMaximumMemoryKiB, parameters.MemoryKiB)
	}
	maximumPasses := max(args.MaximumPasses, parameters.Passes)
	if args.MaximumPasses == 0 {
		maximumPasses = max(DefaultMaximumPasses, parameters.Passes)
	}
	switch {
	case parameters.MemoryKiB < 8*uint32(max(parameters.Lanes, 1)) || parameters.MemoryKiB > 1<<22:
		return nil, fmt.Errorf("memory %d KiB is out of range", parameters.MemoryKiB)
	case parameters.Passes == 0 || parameters.Lanes == 0:
		return nil, errors.New("passes and lanes must be at least 1")
	case parameters.SaltBytes < minimumSaltBytes || parameters.SaltBytes > maximumSaltBytes:
		return nil, fmt.Errorf("salt must be %d to %d bytes", minimumSaltBytes, maximumSaltBytes)
	case parameters.DigestBytes < minimumDigestBytes || parameters.DigestBytes > maximumDigestBytes:
		return nil, fmt.Errorf(
			"digest must be %d to %d bytes",
			minimumDigestBytes,
			maximumDigestBytes,
		)
	}
	concurrentHashes := args.ConcurrentHashes
	if concurrentHashes <= 0 {
		concurrentHashes = min(max(runtime.GOMAXPROCS(0), 1), 4)
	}
	memoryLimitKiB := max(
		int64(concurrentHashes)*int64(parameters.MemoryKiB),
		int64(maximumMemoryKiB),
	)
	wait := args.Wait
	if wait <= 0 {
		wait = DefaultWait
	}
	return &Hasher{
		parameters:       parameters,
		maximumMemoryKiB: maximumMemoryKiB,
		maximumPasses:    maximumPasses,
		memory:           semaphore.NewWeighted(memoryLimitKiB),
		wait:             wait,
	}, nil
}

// reserveMemory waits up to the Hasher's wait for memoryKiB of its budget and
// returns its release.
func (h *Hasher) reserveMemory(ctx context.Context, memoryKiB uint32) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(ctx, h.wait)
	defer cancel()
	if err := h.memory.Acquire(waitCtx, int64(memoryKiB)); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrBusy
	}
	return func() { h.memory.Release(int64(memoryKiB)) }, nil
}

// Hash returns the PHC string of password, hashed with a new random salt.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if len(password) > MaximumLength {
		return "", ErrTooLong
	}
	release, err := h.reserveMemory(ctx, h.parameters.MemoryKiB)
	if err != nil {
		return "", err
	}
	defer release()
	salt := make([]byte, h.parameters.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := argon2.IDKey(
		[]byte(password), salt,
		h.parameters.Passes, h.parameters.MemoryKiB, h.parameters.Lanes, h.parameters.DigestBytes,
	)
	return encode(h.parameters, salt, digest), nil
}

// Matches reports whether password produces encoded, comparing digests in
// constant time. A password longer than MaximumLength never matches. An
// encoded hash that is unreadable, or asks for more memory or passes than the
// Hasher allows, is ErrEncoding.
func (h *Hasher) Matches(ctx context.Context, encoded string, password string) (bool, error) {
	stored, err := decode(encoded)
	if err != nil {
		return false, err
	}
	if stored.parameters.MemoryKiB > h.maximumMemoryKiB ||
		stored.parameters.Passes > h.maximumPasses {
		return false, fmt.Errorf("%w: it asks for more than this hasher allows", ErrEncoding)
	}
	if len(password) > MaximumLength {
		return false, nil
	}
	release, err := h.reserveMemory(ctx, stored.parameters.MemoryKiB)
	if err != nil {
		return false, err
	}
	defer release()
	candidate := argon2.IDKey(
		[]byte(password), stored.salt,
		stored.parameters.Passes, stored.parameters.MemoryKiB, stored.parameters.Lanes,
		uint32(len(stored.digest)),
	)
	return subtle.ConstantTimeCompare(candidate, stored.digest) == 1, nil
}

// NeedsRehash reports whether encoded was made with parameters other than the
// Hasher's, so the caller should hash the password again after it matches.
// An unreadable hash needs rehashing too.
func (h *Hasher) NeedsRehash(encoded string) bool {
	stored, err := decode(encoded)
	if err != nil {
		return true
	}
	return stored.parameters != h.parameters
}

// storedHash is a decoded PHC string.
type storedHash struct {
	parameters Parameters
	salt       []byte
	digest     []byte
}

func encode(parameters Parameters, salt, digest []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, parameters.MemoryKiB, parameters.Passes, parameters.Lanes,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	)
}

func decode(encoded string) (storedHash, error) {
	if len(encoded) > maximumEncodedSize {
		return storedHash{}, ErrEncoding
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return storedHash{}, ErrEncoding
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return storedHash{}, ErrEncoding
	}
	var parameters Parameters
	var trailing string
	scanned, _ := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d%s",
		&parameters.MemoryKiB, &parameters.Passes, &parameters.Lanes, &trailing)
	if scanned != 3 || parameters.MemoryKiB == 0 || parameters.Passes == 0 ||
		parameters.Lanes == 0 ||
		parameters.MemoryKiB < 8*uint32(parameters.Lanes) {
		return storedHash{}, ErrEncoding
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < minimumSaltBytes || len(salt) > maximumSaltBytes {
		return storedHash{}, ErrEncoding
	}
	digest, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(digest) < minimumDigestBytes || len(digest) > maximumDigestBytes {
		return storedHash{}, ErrEncoding
	}
	parameters.SaltBytes = uint32(len(salt))
	parameters.DigestBytes = uint32(len(digest))
	return storedHash{parameters: parameters, salt: salt, digest: digest}, nil
}
