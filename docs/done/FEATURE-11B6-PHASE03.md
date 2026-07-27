# FEATURE-11B6-PHASE03 — RSA service

**Completed:** 2026-07-27
**Branch:** `feature/feature-11b6-phase03-rsa`
**Plan:** `docs/plan/FEATURE-11B6.md` § PHASE03

## Summary

`RsaDataEncryptionService` (method `0x03`) is implemented on PHASE01's seams and PHASE02's
`PayloadCipher`, in the canonical order of `docs/format.md` §7. **No public signature changed.** Three of
the library's five services now work end to end.

Encrypt draws a 32-byte data key and a 12-byte nonce from `IRandomSource`, wraps the key with
`EncryptOaep(…, RsaOaepHash.Sha256)`, writes the 37 + `N` header (which the writer tags and returns), then
runs the shared GCM payload stage with that header as AAD. Decrypt parses and bounds the header, unwraps,
verifies the key-confirmation tag, and only then touches the payload. The wrap happens **before** the
header is built, so an unusable public key leaves the output stream untouched.

Three things are worth recording:

- **The credential-error-vs-file-error distinction was reconciled with what Enigma.Core actually
  reports** (see *Deviations*). A PEM that cannot be parsed keeps its own exception; an OAEP failure —
  wrong key, wrong passphrase or missing passphrase alike — becomes `DataDecryptionException` with the
  original as `InnerException`. `docs/format.md` §9 and the interface XML docs were amended to say so, and
  both halves are asserted by test.
- **The golden vectors pin everything a randomized primitive allows.** OAEP draws its own randomness, so
  256 of the container's 354 bytes cannot be fixed. The suite therefore asserts the 21-byte prefix, the
  length field, the key-confirmation tag and the *whole payload* against a reconstruction from the
  platform's HMAC-SHA256 and `AesGcm`, taking only the wrapped-key bytes from the container under test —
  and separately proves the committed fixture's wrapped key really holds the documented data key
  `00`–`1F`. The limitation is stated in the suite's own XML docs rather than quietly asserted away.
- **Two guards exist that OAEP and key confirmation cannot provide between them.** A hostile *sender* holds
  the recipient's public key, so it can wrap any number of bytes and compute a matching tag for whatever it
  wrapped. The service therefore rejects an unwrapped "data key" whose length is not 32 bytes as a format
  error, and clears it first. Both cases are built and asserted.

## Files/modules touched

### Modified — library

| File | Change |
|---|---|
| `Services/RsaDataEncryptionService.cs` | Both methods implemented: synchronous argument validation, then the §7.1/§7.2 order in private cores; `UnwrapDataKey` translates the OAEP failure and enforces the 32-byte length |
| `Services/IRsaDataEncryptionService.cs` | Three `<exception>` entries reworded for the amended §9 (unparseable PEM propagates as `ArgumentException`/`FormatException`; an undecryptable PEM is a `DataDecryptionException` carrying the cause; the wrapped key must hold a 32-byte data key) |

### Modified — docs

| File | Change |
|---|---|
| `docs/format.md` | §9: the RSA OAEP row now covers an undecryptable private-key PEM; the malformed-PEM row names `ArgumentException`/`FormatException`; a new row for a wrapped key that unwraps to the wrong length; a note explaining why the undecryptable-PEM case cannot be separated |
| `docs/roadmap.md`, `docs/plan/FEATURE-11B6.md` | `PHASE03` → `IN PROGRESS`, then `DONE` |

### Created — tests (`tests/Enigma.DataEncryption.UnitTests/Services/`)

| File | Covers |
|---|---|
| `RsaKeyFixture.cs` | Generate-once key material shared by every RSA suite through a collection fixture: 2048/3072/4096, an unrelated pair, and an encrypted PEM (~2 s once, instead of per class) |
| `RsaTestData.cs` | The §3.3 offsets written out by hand, the golden inputs, the committed-fixture accessors, and the container helpers |
| `RsaTestDoubles.cs` | `FixedDataKeyAndNonceSource`, `RecordingRandomSource`, `RecordingPublicKeyServiceFactory`, and `PoisonedPublicKeyServiceFactory` (the RSA analogue of PHASE02's poisoned KDFs) |
| `RsaRoundTripTests.cs` | 4 ciphers, 3 key sizes with the variable-length field asserted, empty/1-byte/8 MiB payloads, streaming evidence, non-seekable drip-fed input, stream lifetime and position, progress, fresh key/nonce per call, and both encrypted-PEM flavours |
| `RsaFailureTests.cs` | Wrong key (and its timing), a key of another size, a wrong-but-well-formed wrapped key, a wrapped key of the wrong length, the credential-vs-file split in both directions, payload and header tampering at every byte, truncation at every header offset, the length field out of bounds with no unwrap attempted, tightened limits, method mismatch, and a corruption sweep asserting no undocumented type escapes |
| `RsaArgumentValidationTests.cs` | The matrix across both methods, asserting `paramName`, constructor null-guards, and that a rejected call writes nothing and touches no key |
| `RsaCancellationTests.cs` | Pre-cancelled (proved to precede the RSA operation) and mid-payload cancellation, both directions |
| `RsaGoldenVectorTests.cs` | The committed containers' layout, their independent reconstruction, the read path (unencrypted and encrypted PEM), and the write path pinned byte-exactly except the wrapped key |
| `RsaKeyMaterialClearingTests.cs` | The clearing contract on both sides — the generated key on encrypt, the unwrapped key on decrypt — on success and on three failure paths |
| `ContainerFixtures.cs` | The shared fixture reader and plaintext generator both method families now use |
| `Fixtures/rsa-2048-{public,private,private-encrypted}.pem`, `Fixtures/rsa-{aes,twofish}.bin` | The committed golden key pair (test-only material) and the two 354-byte containers |

### Modified — tests

- `Services/TestStreams.cs` — `CountingSink` moved here from `PasswordRoundTripTests`, so both method
  families share the streaming-evidence sink.
- `Services/PasswordRoundTripTests.cs` — uses the shared `CountingSink`.
- `Services/PasswordTestData.cs` — `Fixture` and `Plaintext` now delegate to `ContainerFixtures`; no
  behaviour change, no call-site change.

## Deviations & follow-ups

- **The wrong-key vs undecryptable-PEM distinction the plan asked for is not observable, and the spec was
  amended rather than faked.** The plan (and §9) required an OAEP unwrap failure to become
  `DataDecryptionException` while a wrongly-passworded private-key PEM propagated unwrapped. Enigma.Core
  reports both — and an encrypted PEM opened with *no* passphrase — as the same
  `CryptographicException` from the same `DecryptOaep` call, and their BouncyCastle inner types overlap
  (`InvalidCipherTextException` appears in both a wrong-passphrase failure and a corrupt-ciphertext
  failure), so only the message text distinguishes them. Options were put to the maintainer: probe the PEM
  on the failure path with a throwaway signature, sniff the PEM for encrypted-PEM markers, or wrap and
  amend the document. **The maintainer chose to wrap and amend.** All OAEP failures are now
  `DataDecryptionException` with the cause preserved as `InnerException`; the credential-vs-file split
  still holds for every PEM that cannot be *parsed*, because `ArgumentException` and `FormatException` are
  unambiguous. `docs/format.md` §9 and the interface XML docs record this, and
  `AnUndecryptablePrivateKeyPemIsADecryptionErrorWithTheCauseInside` plus
  `AnUnparseablePrivateKeyPemPropagatesUnwrapped` assert both halves.
- **`FormatException` is a third credential-supply exception the mapping table did not name.** A PEM whose
  Base64 body is invalid fails inside `Convert.FromBase64String`, which Enigma.Core does not catch, so
  neither do we. §9 and the XML docs now name it alongside `ArgumentException`.
- **A wrapped key that does not unwrap to 32 bytes is rejected as a format error** — a check the plan did
  not call for. Only a sender can produce such a container (it needs the recipient's public key), and key
  confirmation is no defence because whoever chose the key material can compute a matching tag; without
  the check, a short "data key" would reach the block cipher and surface as an unwrapped Enigma.Core
  exception, which PHASE05's malformed-input sweep forbids. A row was added to §9; the interface's existing
  `DataEncryptionFormatException` wording already covered it, and was tightened to say so.
- **The key fixture is a collection fixture, not the `IClassFixture` the plan named.** Enigma.Core's
  `RsaKeyFixture` — the precedent the plan cited — is itself an `ICollectionFixture`, and the RSA
  behaviour is split across six classes here; a per-class fixture would have regenerated five key pairs
  six times over. Cost as built: ~2 s once for the whole suite.
- **Key generation is fast enough that 3072 and 4096 needed no special handling** — 344 ms and 794 ms
  respectively on this machine. The whole suite still runs in about twelve seconds (up from six), and
  `RsaFailureTests` deliberately uses small payloads because several of its sweeps perform one RSA
  private-key operation per case.
- **The golden fixtures were generated from the specification, not from the service.** A one-off generator
  built the containers from §3.3 using Enigma.Core's RSA and the platform's HMAC/AES-GCM, so the committed
  bytes never passed through the code they now pin. The Twofish payload is a regression vector, as in
  PHASE02 — no Twofish-GCM implementation exists outside BouncyCastle here — while its header stays
  independent.
- **The committed `rsa-2048-private*.pem` files are test-only key material,** deliberately committed so the
  read-path vectors are reproducible. The encrypted one is a PKCS#8 `ENCRYPTED PRIVATE KEY` (passphrase
  `enigma-test-pem-passphrase`), which also happens to prove Enigma.Core reads that envelope; the fixture
  generated at test time is BouncyCastle's traditional `Proc-Type: 4,ENCRYPTED` envelope, so both flavours
  are exercised.
- **Built in one context rather than delegated to sub-agents.** The plan's delegation note applied to
  PHASE02's two independent services; this phase is one service plus a test suite that shares a key
  fixture, a helper and four doubles, so splitting it would have meant coordinating an interface a single
  context gets for free.
- **PHASE05 follow-up:** the malformed-input sweep should include a wrapped key that unwraps to a non-32-byte
  length in its generated matrix, and the golden-vector consolidation doc should list the three new PEM
  fixtures and the two new containers with their passphrase and expected plaintext.
- **Line endings:** no CRLF/LF inconsistency observed in the files touched; the generated PEM fixtures were
  written with LF. No action taken (recommendation-only per the workflow).

## Build/test evidence

```
dotnet build Enigma.DataEncryption.slnx -c Release --no-incremental
  Build succeeded.  0 Warning(s)  0 Error(s)      (netstandard2.0, net8.0, net10.0)

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  Test run summary: Passed!
  total: 6330   failed: 0   succeeded: 6330   skipped: 0
    net8.0  passed (12s)
    net10.0 passed (10s)
```

73 test methods added by this phase, contributing 224 of the 6,330 cases (PHASE01 + PHASE02 recorded
6,106).

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | Service fully implemented; OAEP-SHA256 used for both directions | Met — no `NotImplementedException` remains in the RSA service; the remaining ones are ML-KEM (PHASE04), the inspector and the file extensions (PHASE05) |
| 2 | Wrong-key, tamper, and over-cap-length cases all produce the documented exception types | Met — wrong key, wrong-size key, wrong-but-well-formed wrapped key, every header byte and every payload region flipped, truncation at every header offset, and the length field at cap+1/0/−1/`int.MinValue`/`int.MaxValue` with no unwrap attempted |
| 3 | The credential-error-vs-file-error distinction holds, asserted by test | Met as amended — an unparseable PEM propagates as `ArgumentException`/`FormatException` on both the public- and private-key sides; an undecryptable PEM is a `DataDecryptionException` carrying the `CryptographicException`, per the maintainer's decision recorded above |
| 4 | Zero-warning Release build; full suite green on both test TFMs | Met |
