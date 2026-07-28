# FEATURE-11B6-PHASE02 — Password-based services (PBKDF2 + Argon2)

**Completed:** 2026-07-27
**Branch:** `feature/feature-11b6-phase02-password`
**Plan:** `docs/plan/FEATURE-11B6.md` § PHASE02

## Summary

`Pbkdf2DataEncryptionService` (method `0x01`) and `Argon2DataEncryptionService` (method `0x02`) are
implemented on PHASE01's seams, in the canonical order of `docs/format.md` §7. Neither has a
`NotImplementedException` left; **no public signature changed.** The first two of the library's five
services now work end to end, and the container they write is pinned byte-for-byte by golden vectors
that were computed outside this library.

Three things are worth recording:

- **The golden vectors are genuinely independent, and stay that way on every run.** The PBKDF2 data key
  was computed with Python's `hashlib.pbkdf2_hmac`, the Argon2id key with OpenSSL 3.6's `ARGON2ID` KDF
  (the exact command is in the test's XML docs), the key-confirmation tags with Python's `hmac`, and the
  AES-256-GCM payloads with the platform's `System.Security.Cryptography.AesGcm`. Beyond the hard-coded
  arrays, `TheGoldenAesContainerIsWhatTheIndependentPrimitivesProduce` rebuilds each AES container from
  platform primitives at run time, so the independence is re-established rather than asserted in a
  comment. The Twofish vectors are labelled for what they are — regression vectors, since no Twofish-GCM
  implementation exists outside BouncyCastle here; their headers are still independent, and only the
  payload bytes come from Enigma.Core.
- **The two timing promises are proved, not asserted.** A wrong password fails at key confirmation
  before a payload byte is read — shown with a container whose payload stream throws `IOException` if
  touched at all, and a companion test that the *right* password does reach that stream, so the double is
  not the reason for the pass. An out-of-bounds cost field is rejected before any derivation — shown with
  a key-derivation factory that throws `KdfInvokedException` if it is ever reached, which also covers the
  Argon2-header-claiming-2-TiB case the plan singled out.
- **Key clearing is covered by test rather than by inspection.** Recording spies hold the very arrays the
  production code was handed or handed back: the derived data key, both HMAC keys (`K` and `kcKey`), and
  the `char[]` overload's temporary UTF-8 buffer. Each is asserted non-zero at derivation time and zeroed
  once the call returns — including when the call fails at key confirmation or at GCM authentication,
  which is what a `finally` enclosing *all* uses is for. The caller's own `byte[]` password is asserted
  unchanged through the same spy.

## Files/modules touched

### Created — library (`src/Enigma.DataEncryption/Internal/`)

| File | Role |
|---|---|
| `PayloadCipher.cs` | The shared payload stage: one GCM operation with the header as AAD, the four fixed §4 parameters applied in one place, and `CryptographicException` → `DataDecryptionException` on the decrypt side only |
| `PasswordCredential.cs` | Password validation for both credential forms, and the UTF-8 encoding of the `char[]` form into a buffer the caller of it clears |

### Modified — library

| File | Change |
|---|---|
| `Services/Pbkdf2DataEncryptionService.cs` | All four overloads implemented; synchronous argument validation, then the §7.1/§7.2 order in a private core |
| `Services/Argon2DataEncryptionService.cs` | The same, with the three Argon2 cost parameters; `DeriveKey` is called with named arguments |

### Created — tests (`tests/Enigma.DataEncryption.UnitTests/Services/`)

| File | Covers |
|---|---|
| `PasswordMethod.cs` | The method enum the shared theories are driven by |
| `PasswordServiceAdapter.cs` | One uniform surface over both services, so every cross-cutting property is asserted for both; exposes each header's cost fields so the limit sweep is generated |
| `PasswordTestData.cs` | The fixed password, plaintext and container helpers (shares PHASE01's salt/nonce fixtures) |
| `PasswordTestDoubles.cs` | `FixedRandomSource`, the poisoned KDF factories, and a synchronous `IProgress<int>` collector |
| `TestStreams.cs` | The stream doubles: poisoned payload, forward-only drip feed, generated 8 MiB pattern source and verifying sink, cancel-after-N-bytes |
| `GoldenVectorPrimitives.cs` | The platform's PBKDF2, HMAC-SHA256 and AES-GCM, for rebuilding a container without this library |
| `PasswordRoundTripTests.cs` | 8 method × cipher round-trips, empty/1-byte/8 MiB payloads, streaming evidence, non-seekable input, stream lifetime and position, progress, both `char[]` promises, fresh salt/nonce per call |
| `PasswordFailureTests.cs` | Wrong password (and its timing), payload and header tampering at every byte, truncation at every header offset, method mismatch, cost fields out of bounds (and no derivation), tightened limits, and a sweep asserting no undocumented exception type escapes |
| `PasswordArgumentValidationTests.cs` | The full matrix across all eight overloads, asserting `paramName`, and that a rejected call writes nothing and derives nothing |
| `PasswordCancellationTests.cs` | Pre-cancelled (proved to precede the KDF) and mid-payload cancellation, on both directions and both credential forms |
| `Pbkdf2GoldenVectorTests.cs` | The 114-byte AES and Twofish containers, the independent reconstruction, the default 600,000-iteration encoding, and the committed fixtures |
| `Argon2GoldenVectorTests.cs` | The 122-byte AES and Twofish containers, the independent reconstruction, the default costs in specified order, KiB-not-exponent, and the committed fixtures |
| `KeyMaterialClearingTests.cs` | The clearing contract, via recording KDF and HMAC spies, on success and on both failure paths |
| `Services/Fixtures/*.bin`, `golden-plaintext.txt` | Four committed containers and the expected plaintext, copied to output by the csproj glob that `FEATURE-67FD` put in place |

### Modified

- `docs/roadmap.md` — `PHASE02` → `IN PROGRESS`, then `DONE`.
- `docs/plan/FEATURE-11B6.md` — the same for the phase's own status.

## Deviations & follow-ups

- **Two internal helpers were added that PHASE01 did not enumerate.** `PayloadCipher` and
  `PasswordCredential` are not new scope so much as the alternative to writing the same code twice now
  and four times by PHASE04: the GCM parameter set of §4 and the `CryptographicException` translation of
  §9 belong in one place, and PHASE03/PHASE04 will consume `PayloadCipher` unchanged. Both are
  `internal`, so `Api/InternalSurfaceIsolationTests.cs` still passes.
- **Progress is reported as per-chunk increments, not as a running total.** Enigma.Core's block-cipher
  service reports each chunk it processes (4,096 bytes, then a smaller final chunk), so the plan's
  "reported values are non-decreasing" is asserted as the *cumulative* total being non-decreasing, with
  the reports summing to exactly the payload byte count — 53 or 61 short of the container length, which is
  what "header bytes are not counted" means. The library forwards `progress` untouched, per the plan.
  Tests use a synchronous collector rather than `Progress<int>`, whose callbacks post through a
  synchronization context and would race the assertions.
- **An undefined `Cipher` raises `ArgumentOutOfRangeException`,** via PHASE01's
  `CipherResolver.ValidateArgument`, which is what the plan specifies. The interface XML docs name
  `ArgumentException` for that case; since `ArgumentOutOfRangeException` derives from it, both hold, and
  the test asserts both. No doc change was needed.
- **A pre-cancelled token is checked before the salt and nonce are drawn**, i.e. before the KDF. The plan
  did not place the check; putting it first is what makes "a cancelled call must not spend 600,000
  iterations" true, and the cancellation tests use the poisoned KDF factory to prove the ordering.
- **Cost parameters in the shared suites are deliberately small** (1,000 PBKDF2 iterations; 1 pass over
  1,024 KiB with one Argon2 lane), so the whole suite still runs in about six seconds. The production
  defaults are pinned separately by the golden vectors, which do encrypt at 600,000 iterations and at
  3 passes over 64 MiB.
- **Built in one context rather than delegated to two sub-agents,** as the plan's delegation note
  suggested. The shared `PayloadCipher`, the shared `PasswordCredential` and the single adapter-driven
  test harness cross both services, so splitting them would have meant coordinating an interface between
  two agents that a single context gets for free.
- **Per-field tamper expectations are a union where the format makes them one.** Flipping a bit in the
  cipher byte can land on another *valid* cipher (`0x01` → `0x03`), which is caught by key confirmation
  rather than by parsing — so the byte-by-byte sweep asserts the outcome is one of the two documented
  exception types, and separate targeted tests pin the specific type for the cases where only one is
  possible (magic, version, an undefined cipher byte, another valid cipher byte).
- **No spec drift found.** `docs/format.md` needed no correction: §3.1, §3.2, §6 and §7 all matched what
  the implementation wanted to do, and the golden vectors were transcribed from the document rather than
  from the code. PHASE05 re-verifies the whole document.
- **Line endings:** no CRLF/LF inconsistency observed in the files touched. No action taken
  (recommendation-only per the workflow).

## Build/test evidence

```
dotnet build Enigma.DataEncryption.slnx -c Release --no-incremental
  Build succeeded.  0 Warning(s)  0 Error(s)      (netstandard2.0, net8.0, net10.0)

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  Test run summary: Passed!
  total: 6106   failed: 0   succeeded: 6106   skipped: 0
    net8.0  passed
    net10.0 passed
```

82 test methods added by this phase, contributing 404 of the 6,106 cases (PHASE01 recorded 5,702).

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | Both services fully implemented; no `NotImplementedException` remains in either | Met — the remaining ones are RSA (PHASE03), ML-KEM (PHASE04), the inspector and the file extensions (PHASE05) |
| 2 | Golden vectors pass in both directions; fixture files committed and copied to output by the existing glob | Met — four containers, write path and read path, plus a run-time reconstruction from platform primitives |
| 3 | Wrong password is proven to fail at the key-confirmation stage, not the GCM stage | Met — `TheWrongPasswordFailsBeforeThePayloadIsRead`, with `TheRightPasswordDoesReachThePayload` as the control |
| 4 | Over-cap Argon2 memory is proven not to allocate | Met — `ACostFieldOutOfBoundsIsAFormatErrorWithNoDerivation` covers every cost field at cap+1, 0, −1, `int.MinValue` and `int.MaxValue` through a factory that throws if reached; `ACostFieldAtItsCapPassesValidation` shows the boundary is inclusive |
| 5 | All key material cleared in `finally`; verified by inspection and recorded in the completion doc | Met, and stronger than required — `KeyMaterialClearingTests` asserts it on the actual buffers, on the success path and on two failure paths |
| 6 | Zero-warning Release build; full suite green on both test TFMs | Met |
