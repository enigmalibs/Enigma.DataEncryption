# FEATURE-11B6-PHASE04 — ML-KEM service

**Completed:** 2026-07-28
**Branch:** `feature/feature-11b6-phase04-mlkem`
**Plan:** `docs/plan/FEATURE-11B6.md` § PHASE04

## Summary

`MLKemDataEncryptionService` (method `0x04`) is implemented on PHASE01's seams and PHASE02's
`PayloadCipher`, in the canonical order of `docs/format.md` §7. **No public signature changed.** All four
encryption services now work end to end; the only `NotImplementedException`s left in the library are the
inspector and the twelve file-path extensions, both PHASE05's.

Encrypt draws a 12-byte nonce from `IRandomSource` — **and nothing else**: `Encapsulate` produces the
32-byte shared secret that *is* the data key (§3.4), so this is the one method that generates no key
material of its own. It then writes the 38 + `N` header (which the writer tags and returns) and runs the
shared GCM payload stage with that header as AAD. Decrypt parses and bounds the header, decapsulates under
the parameter set the *header* names, verifies the key-confirmation tag, and only then touches the payload.
The encapsulation happens **before** the header is built, so a public key Enigma.Core cannot use leaves the
output stream untouched.

Three things are worth recording:

- **This is the phase the key-confirmation tag was designed for, and the premise is now proved rather than
  asserted.** `ImplicitRejectionMeansDecapsulationItselfCannotDetectTheWrongKey` shows, against Enigma.Core
  directly and for all three parameter sets, that decapsulating with a well-formed but wrong private key
  *succeeds* and returns a different 32-byte secret. `TheWrongPrivateKeyFailsBeforeThePayloadIsRead` then
  shows the tag catches it first: the container's payload is a stream that throws if read at all, the
  exception message names the key-confirmation tag, and nothing was written to the output.
- **The decrypt side's exception mapping was reconciled with what Enigma.Core actually reports** (see
  *Deviations*), following the precedent PHASE03 settled. The encrypt side keeps the documented
  `ArgumentException` exactly, because there the ambiguity does not exist.
- **The golden vectors pin the read path completely and the write path as far as a randomized primitive
  allows.** Encapsulation draws its own randomness, so the encapsulation *and the shared secret it carries*
  are fresh per call — 1,568 of the 1024-bit container's 1,667 bytes. The read-path vectors therefore commit
  the key pair **and** the shared secret, so `TheCommittedEncapsulationYieldsTheCommittedSecret` pins the KEM
  itself and everything downstream is a fixed byte sequence. The write path asserts the 22-byte prefix, the
  length field, the key-confirmation tag and the whole payload against a reconstruction from the platform's
  HMAC-SHA256 and `AesGcm`, taking only the encapsulation from the container under test. The limitation is
  stated in the suite's own XML docs rather than quietly asserted away.

## Files/modules touched

### Modified — library

| File | Change |
|---|---|
| `Services/MLKemDataEncryptionService.cs` | Both methods implemented: synchronous argument validation, then the §7.1/§7.2 order in private cores; `Encapsulate` translates an encapsulation failure to `ArgumentException` on `publicKey`, `Decapsulate` translates a decapsulation failure to `DataDecryptionException` |
| `Services/IMLKemDataEncryptionService.cs` | Two `<exception>` entries reworded: `EncryptAsync`'s `ArgumentException` now says "malformed or the wrong length"; `DecryptAsync`'s wrong-length-private-key case moved from `ArgumentException` to `DataDecryptionException`, with the reason stated |
| `Internal/MLKemParameterSetWire.cs` | Added `ValidateArgument(parameterSet, paramName)`, mirroring `CipherResolver.ValidateArgument`, so a caller-supplied parameter set faults **synchronously** rather than inside Enigma.Core's factory after the call has started |

### Modified — docs

| File | Change |
|---|---|
| `docs/format.md` | §9: two new rows — ML-KEM decapsulation failure → `DataDecryptionException`, ML-KEM encapsulation failure → `ArgumentException` on `publicKey` — plus a note explaining why the two directions are deliberately asymmetric |
| `docs/roadmap.md`, `docs/plan/FEATURE-11B6.md` | `PHASE04` → `IN PROGRESS`, then `DONE` |
| `CLAUDE.md` | Documentation freshness sweep, at the maintainer's selection: the *Current state* opening and the PHASE04/PHASE05 status lines refreshed (one `NotImplementedException` service left, not two), and the §9 note gained the ML-KEM sibling of PHASE03's rule — including why the two ML-KEM directions are asymmetric on purpose |

### Created — tests (`tests/Enigma.DataEncryption.UnitTests/Services/`)

| File | Covers |
|---|---|
| `MLKemKeyFixture.cs` | Generate-once key material shared by every ML-KEM suite through a collection fixture: a pair and an unrelated pair for each of the three parameter sets |
| `MLKemTestData.cs` | The §3.4 offsets written out by hand, the encapsulation length and wire byte per parameter set (both transcribed from the spec, not read from `MLKemParameterSetWire`), the committed-fixture accessors, and the container helpers |
| `MLKemTestDoubles.cs` | `FixedNonceSource` (which **refuses** any non-nonce request), `RecordingMLKemServiceFactory` (one double covers both directions), and `PoisonedMLKemServiceFactory` |
| `MLKemRoundTripTests.cs` | 4 ciphers × 3 parameter sets, the default asserted from the produced header byte, the length field per set, empty/1-byte/8 MiB payloads, streaming evidence, non-seekable drip-fed input, stream lifetime and position, progress, fresh nonce+encapsulation per call, that no data key is drawn, and that the parameter set comes from the caller then from the header |
| `MLKemFailureTests.cs` | Implicit rejection demonstrated against Enigma.Core; the wrong key and its timing; a key for another parameter set; a key of the wrong length; a header tagged under another secret; an unusable public key in four shapes and every declared/actual parameter-set mismatch; payload and header tampering at every byte; truncation at every header offset; undefined and cross-valid parameter-set bytes; the length field out of bounds with no decapsulation attempted; tightened limits; method mismatch; and a corruption sweep asserting no undocumented type escapes |
| `MLKemArgumentValidationTests.cs` | The matrix across both methods, asserting `paramName` and declaration order, that the caller's key arrays survive, constructor null-guards, and that a rejected call writes nothing and touches no key |
| `MLKemCancellationTests.cs` | Pre-cancelled (proved to precede the KEM operation) and mid-payload cancellation, both directions |
| `MLKemGoldenVectorTests.cs` | The committed keys' and containers' layout and lengths, the KEM pinned by the committed secret, the independent reconstruction, the read path, and the write path pinned byte-exactly except the encapsulation |
| `MLKemKeyMaterialClearingTests.cs` | The clearing contract on both sides — the encapsulated secret on encrypt, the decapsulated one on decrypt — on success and on three failure paths |
| `Fixtures/mlkem-{512,1024}-{public,private}.key`, `Fixtures/mlkem-{512,1024}-secret.bin`, `Fixtures/mlkem-{1024-aes,1024-twofish,512-aes}.bin` | The committed golden key pairs and their shared secrets (test-only material), and the three containers — 1,667 bytes at ML-KEM-1024, 867 at ML-KEM-512 |

### Modified — tests

- `Services/TestStreams.cs` — added `ThrowAfterStream`, a sink that accepts the header and then fails. ML-KEM
  needs it: an unusable public key fails at encapsulation, *before* a shared secret exists, so the encrypt
  side's `finally` can only be exercised by a failure that happens after the secret is established. (RSA's
  equivalent test could just pass a bad PEM, because its data key is generated before the wrap.)

## Deviations & follow-ups

- **A wrong-length ML-KEM private key is a `DataDecryptionException`, not the `ArgumentException` the
  interface's XML docs promised — the docs were amended.** The plan's PHASE04 note and the FEATURE-00E7 XML
  contract disagreed on this one clause. Enigma.Core settles it: `Decapsulate` raises a single
  `CryptographicException` whose own message names three causes at once — *"The ciphertext or private key may
  be malformed or for a different parameter set."* Two of those point in opposite directions: a wrong-length
  key is the **caller's**, an edited parameter-set byte is the **container's**. They are not separable without
  matching on message text, which CLAUDE.md and §9 already forbid on PHASE03's authority. Reporting an
  argument error for a tampered file is the worse of the two mistakes — and would also fail PHASE05's
  malformed-input sweep, which admits only `DataEncryptionFormatException` and `DataDecryptionException` — so
  all decapsulation failures are wrapped, with the cause kept as `InnerException`. The plan's own test
  expectations ("wrong private key of a different parameter set → `DataDecryptionException`") are met
  unchanged. §9 gained a row and a note; `APrivateKeyOfTheWrongLengthIsADecryptionErrorWithTheCauseInside`
  asserts it.
- **The encrypt side is deliberately *not* symmetrical, and keeps the documented `ArgumentException`.**
  `Encapsulate` takes the public key and nothing else, so its `CryptographicException` can only be about the
  key the caller supplied. It is translated to `ArgumentException` on `publicKey` with the cause preserved,
  which honours the XML docs exactly and matches what Enigma.Core's own RSA path already reports for an
  unusable public key. No FIPS 203 key sizes are hard-coded anywhere in the library to achieve this.
- **The plan left the edited-parameter-set-byte outcome open; it is `DataDecryptionException`, and the test
  documents why.** The header still parses and the length still passes its bounds check, but the reader then
  builds a KEM for the parameter set the byte now claims and hands it a ciphertext and key sized for the real
  one. Every set has distinct ciphertext and key lengths (768/1,088/1,568 and 1,632/2,400/3,168), so
  decapsulation cannot succeed. Were they ever to coincide, the key-confirmation tag — which covers this
  byte — would catch it instead. Asserted for all six written/claimed pairs.
- **No length check on the decapsulated secret, unlike the RSA service's 32-byte guard.** FIPS 203 fixes the
  shared-secret length at 32 bytes independently of the ciphertext, so no sender can influence it; the RSA
  guard exists only because a sender holding the recipient's public key chooses what gets wrapped.
  Adding one here would be untestable dead code. The asymmetry is explained in `Decapsulate`'s XML docs
  rather than left as a silent omission.
- **`ValidateArgument` was added to `MLKemParameterSetWire`, a PHASE01 file.** Additive and internal.
  Enigma.Core's factory would reject an undefined parameter set anyway, but only after the async body had
  started; validating here keeps the "arguments fault synchronously, in declaration order" property the other
  three services already have.
- **The key fixture is a collection fixture, as PHASE03's was.** The plan named `IClassFixture`; the ML-KEM
  behaviour is split across six classes, and ML-KEM key generation is cheap enough (a few ms for all six
  pairs) that the choice is about consistency of the wrong-key material across suites rather than cost.
- **The golden fixtures were generated from the specification, not from the service.** A one-off generator
  built the containers from §3.4 using Enigma.Core's ML-KEM and the platform's HMAC/AES-GCM, so the committed
  bytes never passed through the code they now pin. The Twofish payload is a regression vector, as in PHASE02
  and PHASE03 — no Twofish-GCM implementation exists outside BouncyCastle here — while its header stays
  independent. Verified non-vacuous: flipping one bit inside a committed encapsulation fails three tests (the
  independent reconstruction, the KEM pinning, and the read path).
- **The 1024 pair's two containers share one encapsulation, and therefore one shared secret.** Unlike RSA —
  where a fixed data key is wrapped afresh each time — an ML-KEM secret is determined by its encapsulation,
  so reusing one lets a single committed `mlkem-1024-secret.bin` pin both containers, which then differ only
  in the cipher byte (and, through the tag and AAD, in everything after it).
- **The committed `mlkem-*-private.key` files are test-only key material,** deliberately committed so the
  read-path vectors are reproducible. ML-KEM-512 is included alongside ML-KEM-1024 specifically so a
  non-default parameter-set byte is exercised from a committed file rather than only from a container the
  test just built.
- **Built in one context rather than delegated to sub-agents.** One service plus a test suite that shares a
  key fixture, a helper and three doubles; splitting it would have meant coordinating an interface a single
  context gets for free. (The plan's delegation note applied to PHASE02's two independent services.)
- **PHASE05 follow-ups:** the malformed-input sweep should include the cross-valid parameter-set-byte edits
  and the encapsulation-length matrix from this phase; the golden-vector consolidation doc should list the
  four new `.key` files, the two `.bin` secrets and the three new containers with their parameter set, cipher
  and expected plaintext; and `ThrowAfterStream` is available for the file-extension tests that need a write
  to fail.
- **Line endings:** no CRLF/LF inconsistency observed in the files touched — all new `.cs` and `.md` files are
  LF. No action taken (recommendation-only per the workflow).

## Build/test evidence

```
dotnet build Enigma.DataEncryption.slnx -c Release --no-incremental
  Build succeeded.  0 Warning(s)  0 Error(s)      (netstandard2.0, net8.0, net10.0)

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  Test run summary: Passed!
  total: 6636   failed: 0   succeeded: 6636   skipped: 0
    net10.0 passed (15s)
    net8.0  passed (10s)
```

77 test methods added by this phase, contributing 306 of the 6,636 cases (PHASE01–PHASE03 recorded 6,330).

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | All three parameter sets round-trip with all four ciphers | Met — `RoundTripsExactly` and `TheContainerIsHeaderPlusCiphertextPlusTag` are theories over all twelve combinations, and the encapsulation-length field is asserted against §3.4's 768/1,088/1,568 for each set |
| 2 | Default is ML-KEM-1024, asserted from the produced header bytes | Met — `TheDefaultParameterSetIsMLKem1024` omits the argument entirely and asserts byte 5 is `0x03`, the length field is 1,568 and the container is 1,606 + payload + 16 bytes long |
| 3 | Early wrong-key detection proven by test, with evidence the payload was not read | Met — `TheWrongPrivateKeyFailsBeforeThePayloadIsRead` (all three parameter sets) uses a payload stream that throws if touched, asserts `PayloadWasRead` is false and the output empty, and checks the message names the key-confirmation tag; `ImplicitRejectionMeansDecapsulationItselfCannotDetectTheWrongKey` first establishes that decapsulation cannot report the wrong key at all |
| 4 | Zero-warning Release build; full suite green on both test TFMs | Met |
