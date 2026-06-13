# OPAQUE Library Implementation Mismatches

The server uses two different OPAQUE implementations in the same auth flow:

| Component        | Library                                       | Language         |
| ---------------- | --------------------------------------------- | ---------------- |
| Server (handler) | `bytemare/opaque v0.18.0`                     | Go               |
| Browser client   | `opaque-ke v4.0.0` via `@serenity-kit/opaque` | Rust/WebAssembly |

Both implement [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807), but they differ in default KSF parameters — and these parameters are **bound into the envelope** during registration. Any mismatch between registration and login produces a different `randomized_password`, causing the envelope auth tag check or masking to fail.

## Known mismatches

| Setting           | Go (`bytemare/opaque`)    | Rust (`opaque-ke`)          | Effect                                                              |
| ----------------- | ------------------------- | --------------------------- | ------------------------------------------------------------------- |
| KSF salt          | `nil` (default)           | `[0; 16]` (16 zero bytes)   | Different Argon2id output                                           |
| KSF output length | 32 bytes (element length) | 64 bytes (hash output size) | Different HKDF-Extract IKM length → different `randomized_password` |

A different KSF algorithm (e.g. scrypt vs Argon2id) or different algorithm parameters (time, memory, parallelism) would cause the same class of failure.

## Mitigation (current)

Explicit KSF options matching the WASM client since they can't be changed from WASM:

```go
&opaque.ClientOptions{
    KSFSalt:       make([]byte, 16),
    KSFLength:     64,
    KSFParameters: []uint64{3, 65536, 4},
}
```

## Future improvement

KSF parameters could be stored per-user in the DB and returned alongside the KE2, allowing gradual upgrades (different users can use different KSF settings). This would require schema changes and protocol wire updates.
