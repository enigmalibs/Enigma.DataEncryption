# FEATURE-11B6-PHASE01 — Shared format infrastructure

**Completed:** 2026-07-27
**Branch:** `feature/feature-11b6-phase01-format-infra`
**Plan:** `docs/plan/FEATURE-11B6.md` § PHASE01

## Summary

Implemented the internal machinery every encryption service will sit on: a header writer that seals and
emits all four header shapes, a header reader that parses them while tee-ing the exact bytes it
consumes, and the supporting pieces — cipher resolution, key confirmation, limit validation,
constant-time comparison and buffer clearing.

**No public signature changed, and no public behaviour is unlocked.** The four services and the
inspector still throw `NotImplementedException`; everything added here is `internal` and is exercised
through `InternalsVisibleTo`. PHASE02–PHASE04 consume these seams.

Three decisions worth recording:

- **The associated data is tee-ed, not re-serialized.** `HeaderReader` wraps the input in a private
  read-through `TeeStream` that mirrors every consumed byte into a `MemoryStream`. Tee-ing at each call
  site would not have worked: `ReadLengthValueAsync` consumes its own 4-byte length prefix inside
  Enigma.Core, where a call-site tee cannot see it. Wrapping the stream makes "the AAD is what was on
  the wire" structurally true, which is the property the plan called out as a trap.
- **Both of Enigma.Core's stream failures are translated at the reader boundary.** `IOException` (stream
  ended early) and `InvalidOperationException` (length-value out of range) both become
  `DataEncryptionFormatException`, with the original preserved as the inner exception.
- **Limit validation lives inside `HeaderReader`, not in the callers.** The plan's decrypt order is
  "parse header → validate limits → derive `K`"; putting the `LimitsValidator` calls in the reader
  satisfies that ordering by construction and — the deciding factor — honours
  `IEncryptedDataInspector.ReadHeaderAsync`'s documented contract, which takes a `limits` argument and
  promises `DataEncryptionFormatException` for an out-of-bounds cost or length field. A service-side
  check would have left the inspector reporting values it had never bounded.

## Files/modules touched

### Created — library (`src/Enigma.DataEncryption/Internal/`)

| File | Role |
|---|---|
| `HeaderWriter.cs` | Builds, tags, writes and returns each of the four header shapes |
| `HeaderReader.cs` | Parses a header, tees the AAD, translates Enigma.Core's stream failures; contains the private `TeeStream` |
| `ParsedHeader.cs` | Internal carrier: the public `EncryptedDataHeader`, the raw AAD bytes, and the method-specific key material |
| `CipherResolver.cs` | `Cipher` ↔ header byte, and `Cipher` → `IBlockCipherService`; keeps the format-error and argument-error paths distinct |
| `KeyConfirmation.cs` | `kcKey` / `kcTag` derivation and constant-time verification |
| `LimitsValidator.cs` | Bounds every cost and length field before any allocation or KDF work |
| `CryptoHelpers.cs` | `FixedTimeEquals` and `Clear(params byte[]?[])` |
| `FormatLayout.cs` | Magic bytes and the four header lengths, computed from `DataEncryptionDefaults` |
| `MLKemParameterSetWire.cs` | Explicit `MLKemParameterSet` ↔ wire-byte mapping |

`FormatLayout`, `MLKemParameterSetWire` and `ParsedHeader` are supporting plumbing the plan's nine
components share rather than additions to the scope: the writer and reader both need the magic bytes and
the length arithmetic, both need the parameter-set mapping, and the reader needs somewhere to return the
material `EncryptedDataHeader` deliberately withholds.

`Internal/RandomSource.cs` (plan component 8) already existed and was already real from `FEATURE-00E7`;
it is unchanged and now has test coverage.

### Created — tests (`tests/Enigma.DataEncryption.UnitTests/`)

| File | Covers |
|---|---|
| `Internal/FormatTestData.cs` | Shared fixed inputs and the four shape builders (helper, not a suite) |
| `Internal/HeaderShape.cs` | The shape enum the header theories are driven by |
| `Internal/HeaderRoundTripTests.cs` | Writer→reader round-trip × 4 shapes × 4 ciphers, AAD byte-identity, payload-offset and non-seekable-stream behaviour |
| `Internal/HeaderGoldenBytesTests.cs` | Hand-written expected header bytes; little-endian `Int32` encoding; field offsets |
| `Internal/HeaderTruncationTests.cs` | Truncation at **every** offset of **every** shape (1,213 cases × 2 paths) |
| `Internal/HeaderValidationTests.cs` | Magic, method (incl. reserved `0x05`), version (incl. the whole legacy range), cipher, parameter-set byte, method mismatch, every cost/length field |
| `Internal/KeyConfirmationTests.cs` | The hard-coded tag vector, plus verification against bit-flipped tags, keys and headers |
| `Internal/LimitsValidatorTests.cs` | Every bound: at cap, one over, zero, negative, `int.MaxValue` |
| `Internal/CryptoHelpersTests.cs` | `FixedTimeEquals` (equal, first byte, last byte, bit flips, lengths, nulls) and `Clear` |
| `Internal/CipherResolverTests.cs` | All four mappings, and both undefined-value paths |
| `Internal/MLKemParameterSetWireTests.cs` | The 1-based wire encoding and why a cast would be wrong |
| `Internal/RandomSourceTests.cs` | Requested length, freshness, no shared array |
| `Api/InternalSurfaceIsolationTests.cs` | Reflection guard: no `Enigma.DataEncryption.Internal` type is exported |

### Modified

- `docs/roadmap.md` — `FEATURE-11B6` → `IN PROGRESS`, `PHASE01` → `DONE`.
- `docs/plan/FEATURE-11B6.md` — item and PHASE01 status.

## Deviations & follow-ups

- **The golden key-confirmation vectors were computed with an independent implementation** (Python's
  `hmac` module, from the formulae in `docs/format.md` §6) rather than with the code under test. Pinning
  a derivation against its own output would assert nothing — an argument swap in
  `ComputeHmac(data, key)` round-trips perfectly.
- **`CipherResolver`'s "four distinct services" assertion is behavioural, not type-based.** Enigma.Core
  returns the same concrete service type for every cipher (the algorithm is configuration, not a
  subclass), so the test encrypts the same plaintext under all four and asserts the four ciphertexts
  differ pairwise. This is the only place in PHASE01 that performs a payload encryption.
- **Truncation-sweep field sizes.** The sweep uses a 256-byte wrapped key (RSA-2048) and a 768-byte
  encapsulation (ML-KEM-512) — both real sizes — giving 1,213 truncation offsets per path. Every field
  boundary of every shape is covered; PHASE05's malformed-input sweep widens this to the remaining
  parameter sets.
- **`HeaderWriter`'s four entry points are `async` rather than expression-bodied.** An earlier
  expression-bodied form (`using MemoryStream …; return SealAndWriteAsync(…);`) disposed the buffer at
  method return, before the returned task completed. It happened to work — everything touching the
  buffer runs before the first `await` — but it is exactly the kind of accident that breaks on a later
  edit, so the buffer's lifetime now encloses the whole operation.
- **No spec drift found.** `docs/format.md` needed no correction for this phase; §3's offsets, §6's
  derivation and §9's error mapping all matched what the implementation wanted to do. PHASE05
  re-verifies the whole document against the finished implementation.
- **Line endings:** no CRLF/LF inconsistency observed in the files touched. No action taken
  (recommendation-only per the workflow).

## Build/test evidence

```
dotnet build Enigma.DataEncryption.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)      (netstandard2.0, net8.0, net10.0)

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  Test run summary: Passed!
  total: 5702   failed: 0   succeeded: 5702   skipped: 0
    net8.0  passed
    net10.0 passed
```

149 test methods, 129 of them added by this phase; 2,851 test cases per TFM.

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | All nine components implemented under `Internal/`, none reachable from the public surface | Met — enforced by `Api/InternalSurfaceIsolationTests.cs` |
| 2 | AAD produced on write and reconstructed on read is byte-identical for all four shapes | Met — `HeaderRoundTripTests`, 16 shape × cipher combinations, asserted against both the writer's return value and the bytes on the wire |
| 3 | `IOException` / `InvalidOperationException` never escape the header boundary | Met — 2,426 truncation assertions plus the length-field cases; inner exception preserved |
| 4 | Key-confirmation tag matches a hard-coded expected vector | Met — `KeyConfirmationTests`, independently computed |
| 5 | `BouncyCastleIsolationTests` still passes | Met |
| 6 | Zero-warning Release build; full suite green on both test TFMs | Met |
