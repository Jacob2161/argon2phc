# Changelog

This module follows semantic versioning. Before v1, a minor version may
change the API; each such change says what callers must do.

## v0.2.0 (2026-11-28)

- Requires Go 1.27, the newest Go release; Go 1.26 is no longer
  supported.
- CI runs staticcheck and govulncheck at the versions pinned in
  `tools/go.mod`, a module of its own that importers never see.

## v0.1.1 (2026-11-27)

- `NewHasherArgs.MaximumMemoryKiB` and `MaximumPasses` each document their
  unit and default. No API change.
- CI also checks formatting, `go mod tidy -diff`, and `govulncheck`.

## v0.1.0 (2026-11-27)

First release.

- `Hasher` hashes passwords with argon2id into PHC strings, with the OWASP
  baseline parameters by default.
- Hashes run within a memory limit, so a flood of sign-ins waits up to
  `Wait` and then fails with `ErrBusy` instead of exhausting memory.
- `Matches` reads the parameters from the stored hash within verification
  limits, and `NeedsRehash` says when a stored hash should be replaced.
- Passwords longer than 1024 bytes are refused with `ErrTooLong`.
