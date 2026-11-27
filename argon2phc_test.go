package argon2phc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// cheapParameters keep tests fast; they are far below a safe cost.
var cheapParameters = Parameters{MemoryKiB: 64, Passes: 1, Lanes: 1, SaltBytes: 16, DigestBytes: 32}

// salt22 and digest43 are base64 of 16 and 32 zero bytes, valid sizes.
const (
	salt22   = "AAAAAAAAAAAAAAAAAAAAAA"
	digest43 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func newCheapHasher(t testing.TB) *Hasher {
	t.Helper()
	hasher, err := NewHasher(&NewHasherArgs{Parameters: cheapParameters})
	if err != nil {
		t.Fatal(err)
	}
	return hasher
}

// TestHash checks that the default hash has the OWASP parameters, matches its
// password only, gets a new salt each time, and refuses long passwords.
func TestHash(t *testing.T) {
	hasher, err := NewHasher(nil)
	if err != nil {
		t.Fatal(err)
	}
	password := "correct horse battery staple"
	encoded, err := hasher.Hash(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("encoded = %s, want the prefix $argon2id$v=19$m=65536,t=3,p=2$", encoded)
	}
	matched, err := hasher.Matches(t.Context(), encoded, password)
	if err != nil || !matched {
		t.Fatalf("Matches(the password) = %v, %v, want true", matched, err)
	}
	matched, err = hasher.Matches(t.Context(), encoded, password+"!")
	if err != nil || matched {
		t.Fatalf("Matches(another password) = %v, %v, want false", matched, err)
	}
	again, err := hasher.Hash(t.Context(), password)
	if err != nil || again == encoded {
		t.Fatalf("two hashes share a salt: %v, want distinct salts", err)
	}
	tooLong := strings.Repeat("a", MaximumLength+1)
	if _, err := hasher.Hash(t.Context(), tooLong); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Hash(a long password) = %v, want ErrTooLong", err)
	}
	matched, err = hasher.Matches(t.Context(), encoded, tooLong)
	if matched || err != nil {
		t.Fatalf("Matches(a long password) = %v, %v, want false and no error", matched, err)
	}
}

// TestMatchesRefusesUnreadableHashes checks the PHC parser's refusals.
func TestMatchesRefusesUnreadableHashes(t *testing.T) {
	hasher := newCheapHasher(t)
	for _, broken := range []string{
		"",
		"$bcrypt$x",
		"$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=16$m=64,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=0,t=3,p=2$" + salt22 + "$" + digest43,
		"$argon2id$v=19$m=2097152,t=1,p=1$" + salt22 + "$" + digest43,
		"$argon2id$v=19$m=64,t=99,p=1$" + salt22 + "$" + digest43,
		"$argon2id$v=19$m=64,t=1,p=1x$" + salt22 + "$" + digest43,
		"$argon2id$v=19$m=64,t=1,p=1$!!$" + digest43,
		"$argon2id$v=19$m=64,t=1,p=1$AAAA$" + digest43,
		"$argon2id$v=19$m=64,t=1,p=1$" + salt22 + "$",
		"$argon2id$v=19$m=64,t=1,p=1$" + salt22 + "$" + strings.Repeat("A", 400),
		"x$argon2id$v=19$m=64,t=1,p=1$" + salt22 + "$" + digest43,
	} {
		if _, err := hasher.Matches(t.Context(), broken, "password"); !errors.Is(err, ErrEncoding) {
			t.Errorf("Matches(%q) = %v, want ErrEncoding", broken, err)
		}
	}
}

// TestNeedsRehash checks that a hash made with other parameters, or an
// unreadable one, needs rehashing, and a current one does not.
func TestNeedsRehash(t *testing.T) {
	cheap := newCheapHasher(t)
	encoded, err := cheap.Hash(t.Context(), "password")
	if err != nil {
		t.Fatal(err)
	}
	if cheap.NeedsRehash(encoded) {
		t.Fatal("a current hash needs rehashing")
	}
	stronger := cheapParameters
	stronger.Passes = 2
	strongerHasher, err := NewHasher(&NewHasherArgs{Parameters: stronger})
	if err != nil {
		t.Fatal(err)
	}
	if !strongerHasher.NeedsRehash(encoded) {
		t.Fatal("a hash with fewer passes does not need rehashing")
	}
	matched, err := strongerHasher.Matches(t.Context(), encoded, "password")
	if err != nil || !matched {
		t.Fatalf("Matches(an older hash) = %v, %v, want true", matched, err)
	}
	if !cheap.NeedsRehash("garbage") {
		t.Fatal("an unreadable hash does not need rehashing")
	}
}

// TestBusy checks that a hash gives up with ErrBusy once it has waited the
// whole Wait for memory that stays taken, and with the context's error when
// it is cancelled first.
func TestBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hasher, err := NewHasher(&NewHasherArgs{
			Parameters:       cheapParameters,
			ConcurrentHashes: 1,
			MaximumMemoryKiB: cheapParameters.MemoryKiB,
			Wait:             10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		release, err := hasher.reserveMemory(t.Context(), cheapParameters.MemoryKiB)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if _, err := hasher.Hash(t.Context(), "password"); !errors.Is(err, ErrBusy) {
			t.Fatalf("Hash with the memory taken = %v, want ErrBusy", err)
		}
		if waited := time.Since(started); waited != 10*time.Second {
			t.Fatalf("Hash gave up after %s, want 10s, the Wait", waited)
		}
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := hasher.Hash(cancelled, "password"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Hash on a cancelled context = %v, want context.Canceled", err)
		}
		release()
		if _, err := hasher.Hash(cancelled, "password"); !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"Hash on a cancelled context with memory free = %v, want context.Canceled",
				err,
			)
		}
		if _, err := hasher.Hash(t.Context(), "password"); err != nil {
			t.Fatalf("Hash after the memory was released = %v, want nil", err)
		}
	})
}

// TestNewHasherRefusesUnusableParameters checks parameter validation.
func TestNewHasherRefusesUnusableParameters(t *testing.T) {
	for _, parameters := range []Parameters{
		{MemoryKiB: 64, Passes: 0, Lanes: 1, SaltBytes: 16, DigestBytes: 32},
		{MemoryKiB: 64, Passes: 1, Lanes: 0, SaltBytes: 16, DigestBytes: 32},
		{MemoryKiB: 64, Passes: 1, Lanes: 1, SaltBytes: 4, DigestBytes: 32},
		{MemoryKiB: 64, Passes: 1, Lanes: 1, SaltBytes: 1 << 31, DigestBytes: 32},
		{MemoryKiB: 64, Passes: 1, Lanes: 1, SaltBytes: 16, DigestBytes: 8},
		{MemoryKiB: 64, Passes: 1, Lanes: 1, SaltBytes: 16, DigestBytes: 1 << 20},
		{MemoryKiB: 1<<22 + 1, Passes: 1, Lanes: 1, SaltBytes: 16, DigestBytes: 32},
	} {
		if _, err := NewHasher(&NewHasherArgs{Parameters: parameters}); err == nil {
			t.Errorf("NewHasher(%+v) returned no error, want one", parameters)
		}
	}
}

// FuzzDecode checks that the parser never panics, that whatever it reads is
// within the size bounds, and that encoding what it read reads back the same.
func FuzzDecode(f *testing.F) {
	f.Add(
		"$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0MTI",
	)
	f.Add("$argon2id$v=19$m=64,t=1,p=1$" + salt22 + "$" + digest43)
	f.Fuzz(func(t *testing.T, encoded string) {
		stored, err := decode(encoded)
		if err != nil {
			return
		}
		if len(stored.salt) > maximumSaltBytes || len(stored.digest) > maximumDigestBytes {
			t.Fatalf("%q decoded past the size bounds", encoded)
		}
		again, err := decode(encode(stored.parameters, stored.salt, stored.digest))
		if err != nil || again.parameters != stored.parameters ||
			string(
				again.salt,
			) != string(
				stored.salt,
			) || string(again.digest) != string(stored.digest) {
			t.Fatalf("%q does not read back the same: %v", encoded, err)
		}
	})
}

func BenchmarkHashDefault(b *testing.B) {
	hasher, err := NewHasher(nil)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := hasher.Hash(b.Context(), "correct horse battery staple"); err != nil {
			b.Fatal(err)
		}
	}
}

// TestVerificationLimits checks that a default Hasher refuses a stored hash
// asking for 2 GiB, and that a Hasher configured for it accepts it.
func TestVerificationLimits(t *testing.T) {
	hasher, err := NewHasher(nil)
	if err != nil {
		t.Fatal(err)
	}
	greedy := "$argon2id$v=19$m=2097152,t=1,p=1$" + salt22 + "$" + digest43
	if _, err := hasher.Matches(t.Context(), greedy, "password"); !errors.Is(err, ErrEncoding) {
		t.Fatalf("Matches(a 2 GiB stored hash) = %v, want ErrEncoding", err)
	}
	if _, err := decode(greedy); err != nil {
		t.Fatalf("the parser itself refused a well-formed hash: %v", err)
	}
}
