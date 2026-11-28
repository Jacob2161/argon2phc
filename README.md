# argon2phc

[![Go Reference](https://pkg.go.dev/badge/github.com/jacob2161/argon2phc.svg)](https://pkg.go.dev/github.com/jacob2161/argon2phc)
[![CI](https://github.com/jacob2161/argon2phc/actions/workflows/ci.yml/badge.svg)](https://github.com/jacob2161/argon2phc/actions/workflows/ci.yml)

Password hashing with argon2id in the PHC string format, with OWASP default parameters,
constant-time checks, rehash detection, and a bound on how many 64 MiB hashes run at once.

```bash
go get github.com/jacob2161/argon2phc
```

## Usage

```go
hasher, err := argon2phc.NewHasher(nil) // OWASP baseline: 64 MiB, t=3, p=2
encoded, err := hasher.Hash(ctx, password)
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<digest>

matched, err := hasher.Matches(ctx, encoded, password)
if matched && hasher.NeedsRehash(encoded) {
	encoded, err = hasher.Hash(ctx, password) // store the upgraded hash
}
```

- A `Hasher` admits hashes against a memory budget, by default GOMAXPROCS (up to 4) times the hash
  memory, so a flood of sign-ins waits, and gives up with `ErrBusy`, instead of exhausting memory.
  Share one Hasher: each has its own budget.
- Stored hashes are checked within verification limits (256 MiB and 16 passes by default,
  configurable), and salts, digests, and encoded strings are bounded before decoding, so a tampered
  hash cannot ask for unbounded memory or time.
- Password policy (minimum length and so on) is yours; only passwords over 1024 bytes are refused,
  which bounds the work per request.
- One default hash takes roughly 40 to 60 ms on a modern core, depending on the machine.

Requires Go 1.27. Licensed under the MIT license.
