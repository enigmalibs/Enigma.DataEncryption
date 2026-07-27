# FEATURE-11B6 — Core implementation

**Status:** IN PROGRESS
**Type:** FEATURE (5 phases)
**Depends on:** FEATURE-00E7

## Objective

Implement every behaviour behind the API surface fixed by FEATURE-00E7, exactly as specified by
`docs/format.md`, with a test suite that pins the binary format byte-for-byte and proves the library
behaves safely on hostile input.

**No public signature changes.** If a signature turns out to be wrong, that is a deviation to record
in the phase's completion doc and to reflect back into `docs/format.md` and the XML docs in the same
dev — not something to paper over.

## Phase overview

| Phase | Title | Suggested branch |
|---|---|---|
| PHASE01 | Shared format infrastructure | `feature/feature-11b6-phase01-format-infra` |
| PHASE02 | Password-based services (PBKDF2 + Argon2) | `feature/feature-11b6-phase02-password` |
| PHASE03 | RSA service | `feature/feature-11b6-phase03-rsa` |
| PHASE04 | ML-KEM service | `feature/feature-11b6-phase04-mlkem` |
| PHASE05 | Inspector, file extensions, DI & robustness suites | `feature/feature-11b6-phase05-integration` |

The ordering is load-bearing: PHASE01 defines the internal seams the next three consume, and PHASE05's
cross-cutting suites (malformed-input sweep, thread-safety) need all four methods present to be
meaningful.

---

## PHASE01 — Shared format infrastructure

**Status:** DONE

### Scope

Internal machinery under `src/Enigma.DataEncryption/Internal/`. No public behaviour is unlocked in
this phase; everything here is exercised directly through `InternalsVisibleTo`.

**1. `HeaderWriter`** — builds a header into a `MemoryStream` using Enigma.Core's
`StreamExtensions` (`WriteBytes`, `WriteByte`, `WriteInt`) and returns the complete byte array.

Because the header **is** the AAD, materializing it in memory is required anyway — so build it fully,
compute the key-confirmation tag over it, append the tag, and write the resulting array to the output
in one `WriteBytesAsync`. This makes "the AAD is exactly what was written" structurally true rather
than a thing to remember.

**2. `HeaderReader`** — parses a header from a stream **while tee-ing every byte it consumes into a
`MemoryStream`**, so the AAD is reconstructed from what was actually read rather than re-serialized
from parsed fields. Re-serializing is the obvious approach and it is a trap: any asymmetry between
writer and reader silently produces a mismatching AAD and a confusing authentication failure.

Returns the parsed `EncryptedDataHeader` plus the raw header bytes.

**3. Truncation translation.** Enigma.Core's `ReadBytesAsync` / `ReadIntAsync` go through
`StreamReadHelpers.ReadExact*`, which throws **`IOException`** when the stream ends early, and
`ReadLengthValueAsync` throws **`InvalidOperationException`** when a length is out of range. Both must
be caught at the header-parsing boundary and translated to `DataEncryptionFormatException`. Missing
this is the single most likely cause of the malformed-input sweep in PHASE05 failing.

**4. `CipherResolver`** — maps `Cipher` to an `IBlockCipherService` through the injected
`IBlockCipherServiceFactory`:

| `Cipher` | Factory call |
|---|---|
| `Aes256Gcm` | `CreateAesService()` |
| `Twofish256Gcm` | `CreateTwofishService()` |
| `Serpent256Gcm` | `CreateSerpentService()` |
| `Camellia256Gcm` | `CreateCamelliaService()` |

Undefined value → `DataEncryptionFormatException` when it came from a header, or
`ArgumentOutOfRangeException` when it came from a caller. Both paths exist; keep them distinct.

**5. `KeyConfirmation`** —

```
kcKey = hmacSha256.ComputeHmac(ASCII("Enigma.DataEncryption/kc/v1"), K)
kcTag = hmacSha256.ComputeHmac(headerBytesBeforeTag, kcKey)[0..16]
```

Note the argument order of `IHmacService.ComputeHmac(byte[] data, byte[] key)` — data first, key
second. Getting these backwards produces a working round-trip that does not match the specification,
which only the golden vectors would catch.

Provide `Verify(...)` using the constant-time comparison below, and clear `kcKey` in a `finally`.

**6. `CryptoHelpers.FixedTimeEquals`** —

```csharp
#if NETSTANDARD2_0
    // XOR-accumulator loop; no early return
#else
    return CryptographicOperations.FixedTimeEquals(left, right);
#endif
```

Length mismatch returns `false` without comparing. Matches the predecessor's approach, which its own
code review endorsed.

**7. `LimitsValidator`** — validates each header cost/length field against `DataEncryptionLimits`,
rejecting `<= 0` as well as over-cap values, and throwing `DataEncryptionFormatException` with a
message naming the field and the cap. **Called before any allocation or KDF work.**

**8. `RandomSource`** — the real `IRandomSource` over `RandomUtils.GenerateRandomBytes`.

**9. Key-clearing convention** — a small helper (`Clear(params byte[]?[] buffers)`) plus the
convention that every derived key, KEM secret and confirmation key is cleared in a `finally` that
encloses **all** of its uses. The predecessor's code review flagged this as its one High-severity
finding, caused by clearing outside `try/finally`. Do not repeat it.

### Tests (PHASE01)

- `HeaderWriter` → `HeaderReader` round-trip for all four method shapes, asserting field values **and**
  that the tee-ed AAD bytes are byte-identical to what the writer produced.
- Offset assertions: header lengths are exactly 53 / 61 / 37+N / 38+N.
- Little-endian `Int32` encoding asserted against hand-written expected bytes (do not assert
  round-trip only — that would pass with either endianness).
- Truncation at every offset within each header shape → `DataEncryptionFormatException`.
- `LimitsValidator`: at cap (accept), one over cap (reject), zero and negative (reject).
- `FixedTimeEquals`: equal, differing at first byte, differing at last byte, different lengths.
- `KeyConfirmation`: a fixed `K` and fixed header produce a fixed expected 16-byte tag (a hard-coded
  vector, so the derivation itself is pinned); `Verify` accepts the right tag and rejects a
  single-bit-flipped one.
- `CipherResolver`: all four map to a non-null service; undefined value throws the right exception on
  each path.

### Acceptance criteria (PHASE01)

1. All nine components implemented under `Internal/`, none reachable from the public surface.
2. The AAD produced on write and reconstructed on read is byte-identical for all four shapes.
3. `IOException` and `InvalidOperationException` from Enigma.Core stream reads never escape the header
   boundary.
4. Key-confirmation tag matches a hard-coded expected vector.
5. `BouncyCastleIsolationTests` still passes.
6. Zero-warning Release build; full suite green on both test TFMs.

---

## PHASE02 — Password-based services (PBKDF2 + Argon2)

**Status:** TODO

### Scope

`Pbkdf2DataEncryptionService` and `Argon2DataEncryptionService`.

**PBKDF2**: `IPbkdf2Service.DeriveKey(password, salt, iterations, keySizeBytes: 32,
Pbkdf2Prf.HmacSha256)`.

**Argon2**: `IArgon2Service.DeriveKey(password, salt, iterations, memorySizeKb, degreeOfParallelism,
keySizeBytes: 32, Argon2Variant.Argon2id, Argon2Version.Version13)`.

Both follow the canonical order from `docs/format.md`:

*Encrypt* — validate args → `IRandomSource` for the 16-byte salt and 12-byte nonce → derive `K` →
build header → kcTag → write header → `EncryptAsync(input, output, K, nonce, BlockCipherMode.Gcm,
PaddingScheme.None, 128, associatedData: header, progress, ct)` → clear.

*Decrypt* — parse header → validate limits → derive `K` → verify kcTag → `DecryptAsync` with the same
AAD → clear.

`char[]` overloads UTF-8-encode into a temporary buffer, delegate, and clear the temporary in a
`finally`. The caller's array is never touched.

Argument validation: null streams / null password → `ArgumentNullException`; empty password →
`ArgumentException`; `iterations`, `memorySizeKb`, `degreeOfParallelism` `<= 0` →
`ArgumentOutOfRangeException`; undefined `Cipher` → `ArgumentOutOfRangeException`. Validate **before**
any work.

> **Delegation note.** The two services are independent given PHASE01's seams, so they split cleanly
> into two sub-agents (one each), given the shared-infrastructure contract and the exact target paths.
> Integrate, then run the full build and suite yourself before declaring the phase done.

### Tests (PHASE02)

- Round-trip × 4 ciphers × 2 methods = 8 combinations, asserting exact plaintext recovery.
- Empty payload round-trip (both methods).
- Large payload — at least 8 MiB — round-trip, asserting correctness and that the operation streams
  rather than buffering the whole payload.
- **Golden vectors, write path:** fixed `IRandomSource` + fixed password/iterations ⇒ exact expected
  byte array, asserted in full. One per method, plus one per cipher for AES/Twofish at minimum.
- **Golden vectors, read path:** committed fixture files decrypt to the exact expected plaintext.
- Wrong password → `DataDecryptionException`, and assert it is raised by the **key-confirmation
  check** (i.e. before the payload is consumed) — e.g. by supplying a large or deliberately unreadable
  payload stream and showing it was never read.
- Tamper: flip one bit in the payload → `DataDecryptionException`. Flip one bit in **each** header
  field in turn → `DataDecryptionException` (AAD/kcTag), or `DataEncryptionFormatException` where the
  edit makes the header structurally invalid. Enumerate the fields; do not spot-check.
- Header cost fields above cap → `DataEncryptionFormatException`; and assert **no allocation or KDF
  work happened** (e.g. an Argon2 header claiming 1 TiB returns promptly rather than attempting it).
- Argument validation matrix, all cases above.
- Cancellation: a token cancelled before the call and during the payload stage both surface
  `OperationCanceledException`.
- Progress: reported values are non-decreasing and total the payload byte count, **excluding** header
  bytes.
- `char[]` overload produces byte-identical output to the `byte[]` overload for the same password, and
  does not mutate the caller's array.

### Acceptance criteria (PHASE02)

1. Both services fully implemented; no `NotImplementedException` remains in either.
2. Golden vectors pass in both directions; fixture files committed and copied to output by the
   existing glob.
3. Wrong password is proven to fail at the key-confirmation stage, not the GCM stage.
4. Over-cap Argon2 memory is proven not to allocate.
5. All key material cleared in `finally`; verified by inspection and recorded in the completion doc.
6. Zero-warning Release build; full suite green on both test TFMs.

---

## PHASE03 — RSA service

**Status:** TODO

### Scope

`RsaDataEncryptionService`.

*Encrypt* — `IRandomSource` for the 32-byte data key and 12-byte nonce → wrap the data key with
`IPublicKeyService.EncryptOaep(key, publicKeyPem, RsaOaepHash.Sha256)` → header (nonce, wrapped-key
length, wrapped key) → kcTag → write → GCM encrypt with the header as AAD → clear.

*Decrypt* — parse header → validate wrapped-key length against `MaxWrappedKeyLength` → unwrap with
`IPublicKeyService.DecryptOaep(wrappedKey, privateKeyPem, RsaOaepHash.Sha256, keyPassword)` → verify
kcTag → GCM decrypt → clear.

Notes:

- Read the wrapped key with `ReadLengthValueAsync(maxLength: limits.MaxWrappedKeyLength)` so
  Enigma.Core's own cap does the first line of defence, translating its `InvalidOperationException`.
- A wrong RSA private key surfaces from Enigma.Core as `CryptographicException` from the OAEP unwrap →
  wrap in `DataDecryptionException`. The key-confirmation tag is the backstop for the (unlikely) case
  where an unwrap yields 32 bytes of the wrong key material.
- A malformed or wrongly-passworded **private-key PEM** propagates unwrapped
  (`ArgumentException` / `CryptographicException` from Enigma.Core) — it is a credential-supply
  problem, not a file-content problem. This distinction is in FEATURE-00E7's mapping table; keep it.
- A 32-byte payload under OAEP-SHA256 needs 98 bytes, so RSA-2048 upward all work. Guard nothing on
  key size; let Enigma.Core report an undersized key.

### Tests (PHASE03)

- Round-trip × 4 ciphers using a generated RSA-2048 key pair, plus one round-trip each at 3072 and
  4096 to confirm the variable-length field behaves.
- Empty payload and large-payload (≥ 8 MiB) round-trips.
- Golden vectors: the wrapped key is randomized by OAEP, so **pin what is deterministic** — the fixed
  header prefix, offsets, field lengths, and full byte-exactness of everything except the wrapped-key
  bytes; plus a committed fixture file (fixed key pair + fixed ciphertext) that decrypts to an exact
  expected plaintext. State this limitation explicitly in the test's comments rather than silently
  asserting less.
- Wrong private key (a second, unrelated key pair) → `DataDecryptionException`.
- Encrypted private-key PEM: correct `keyPassword` succeeds; wrong one propagates Enigma.Core's
  exception unwrapped, per the mapping table.
- Tamper: payload bit-flip, and a bit-flip in each header field including inside the wrapped key.
- Wrapped-key length field set above cap, set negative, set to a value longer than the remaining
  stream → `DataEncryptionFormatException` in each case, with no large allocation.
- Argument validation: null streams, null/empty `publicKeyPem`, null/empty `privateKeyPem`, undefined
  `Cipher`.
- Cancellation and progress, as in PHASE02.

Use a shared RSA key-pair fixture generated once per test class (an `IClassFixture`), as
Enigma.Core's `RsaKeyFixture` does — key generation is slow and must not be repeated per test.

### Acceptance criteria (PHASE03)

1. Service fully implemented; OAEP-SHA256 used for both directions.
2. Wrong-key, tamper, and over-cap-length cases all produce the documented exception types.
3. The credential-error-vs-file-error distinction holds, asserted by test.
4. Zero-warning Release build; full suite green on both test TFMs.

---

## PHASE04 — ML-KEM service

**Status:** TODO

### Scope

`MLKemDataEncryptionService`.

*Encrypt* — `IMLKemServiceFactory.CreateMLKemService(parameterSet)` →
`Encapsulate(publicKey)` → `(ciphertext, sharedSecret)`; `sharedSecret` (32 bytes) **is** the data key
→ `IRandomSource` for the 12-byte nonce → header (parameter-set byte, nonce, encapsulation
length-value) → kcTag → write → GCM encrypt with header as AAD → clear the secret.

*Decrypt* — parse header including the parameter-set byte → validate encapsulation length →
`CreateMLKemService(parameterSetFromHeader).Decapsulate(ciphertext, privateKey)` → verify kcTag → GCM
decrypt → clear.

Notes:

- Parameter-set byte mapping: `01` → `MLKemParameterSet.MLKem512`, `02` → `MLKem768`, `03` →
  `MLKem1024`. Undefined byte → `DataEncryptionFormatException`.
- **This is the phase the key-confirmation tag was designed for.** FIPS 203 implicit rejection means
  `Decapsulate` with a well-formed but wrong private key *succeeds* and returns a different 32-byte
  secret. Without the kcTag the only signal is the GCM tag at the end of the stream. There must be a
  test that specifically proves early failure here.
- A private key of the wrong length or for a different parameter set surfaces from Enigma.Core as
  `CryptographicException` from `Decapsulate` → wrap in `DataDecryptionException`.

### Tests (PHASE04)

- Round-trip × 4 ciphers × 3 parameter sets (512 / 768 / 1024) = 12 combinations.
- Default parameter set is ML-KEM-1024 when the caller does not specify one — asserted by reading the
  header byte of the produced output.
- Empty payload and large-payload (≥ 8 MiB) round-trips.
- Golden vectors: fixed key pair + fixed `IRandomSource`. ML-KEM encapsulation draws its own
  randomness inside Enigma.Core, so — as for RSA — pin the deterministic header portion fully and use
  committed fixture files for the exact-plaintext read-path assertion. Enigma.Core's own
  `tests/.../Pqc/` fixtures (`kem1024_A_private.key`, `encapsulation.bin`, `secret.bin`) are a
  precedent for the fixture style.
- **Wrong private key → `DataDecryptionException` raised at the key-confirmation stage**, proven not to
  have consumed the payload. This is the headline test of the phase.
- Wrong private key of a *different parameter set* → `DataDecryptionException`.
- Header parameter-set byte edited to a different valid value → `DataDecryptionException` (the AAD
  covers it) or `DataEncryptionFormatException` if decapsulation rejects the length first; assert
  whichever the implementation produces and document it.
- Undefined parameter-set byte (`00`, `04`, `FF`) → `DataEncryptionFormatException`.
- Encapsulation length above cap / negative / beyond end of stream → `DataEncryptionFormatException`.
- Tamper, argument validation, cancellation, progress, as in the previous phases.

### Acceptance criteria (PHASE04)

1. All three parameter sets round-trip with all four ciphers.
2. Default is ML-KEM-1024, asserted from the produced header bytes.
3. Early wrong-key detection proven by test, with evidence the payload was not read.
4. Zero-warning Release build; full suite green on both test TFMs.

---

## PHASE05 — Inspector, file extensions, DI & robustness suites

**Status:** TODO

### Scope

**1. `EncryptedDataInspector`** — implements `ReadHeaderAsync` on top of PHASE01's `HeaderReader`,
populating only the properties that apply to the parsed method. Restores the original stream position
when the stream is seekable; leaves it at the payload otherwise (documented in FEATURE-00E7).

**2. `DataEncryptionFileExtensions`** — the file-path pairs for all four services, with the three
documented semantics: async `FileStream`s with `bufferSize: 4096`; output `FileMode.Create`
(create-or-overwrite); and **the partial output file deleted on any failure, including cancellation**,
best-effort so a delete failure never masks the original exception.

**3. `AddEnigmaDataEncryption()`** — the real registrations, per FEATURE-00E7.

**4. Cross-cutting robustness suites** — these need all four methods present, which is why they live
here:

- **Malformed-input sweep.** Systematically corrupt and truncate: bad magic (both bytes,
  independently); every undefined method byte; every reserved version byte `0x00`–`0x0F` and a
  selection above `0x10`; undefined cipher bytes; undefined ML-KEM parameter-set bytes; every cost and
  length field at zero, negative, `int.MaxValue` and one-over-cap; truncation at **every** byte offset
  within each of the four header shapes; a zero-length stream; a 1-byte stream. Assert for every case
  that the exception is `DataEncryptionFormatException` or `DataDecryptionException` and **never**
  `NullReferenceException`, `IndexOutOfRangeException`, `ArgumentOutOfRangeException` from internal
  indexing, `OutOfMemoryException`, or an unwrapped Enigma.Core exception. Drive it as a theory over a
  generated case matrix, not as a handful of hand-written cases.
- **Thread-safety.** For each of the five services, drive one instance concurrently from many tasks
  (encrypt and decrypt distinct payloads) and assert every result is correct. This substantiates the
  singleton registration.
- **DI integration.** Build a real `ServiceProvider` from `AddEnigmaDataEncryption()`; resolve all five
  services; assert each resolves, that repeated resolutions return the **same instance** (singleton),
  and that a full encrypt/decrypt round-trip works through the resolved services. Also assert
  `TryAdd*` semantics: a pre-registered custom `IBlockCipherServiceFactory` survives the call.
- **File-extension tests.** Round-trip through real temp files; existing output file is overwritten;
  and — the important one — **a failed decrypt (wrong password) leaves no output file behind**.
- **Golden-vector consolidation.** One place that documents every committed fixture: which method,
  cipher, parameter set, credential and expected plaintext each corresponds to, so the fixtures remain
  intelligible later.

**5. Coverage.** Collect with `coverlet.collector` and record the figure in the completion doc. No
build gate.

### Acceptance criteria (PHASE05)

1. Inspector implemented, with seekable-restore behaviour asserted both ways.
2. File extensions implemented with all three documented semantics, each asserted — including no
   orphaned output file after a failure.
3. `AddEnigmaDataEncryption()` fully wired; singleton identity and `TryAdd*` survival asserted.
4. Malformed-input sweep is a generated matrix covering every field and every truncation offset for
   all four shapes, and passes.
5. Thread-safety suite passes for all five services.
6. **No `NotImplementedException` remains anywhere in the library.**
7. `BouncyCastleIsolationTests` passes.
8. `docs/format.md` re-verified against the finished implementation; any drift corrected in this dev.
9. Coverage figure recorded in the completion doc.
10. Zero-warning Release build; full suite green on both test TFMs.

---

## Verification (every phase)

```bash
dotnet build Enigma.DataEncryption.slnx -c Release
dotnet test --solution Enigma.DataEncryption.slnx -c Release
```

## Notes for the implementer

- The `IHmacService.ComputeHmac(byte[] data, byte[] key)` argument order is data-then-key. A swap
  round-trips fine and fails only the golden vectors.
- Enigma.Core's `Int32` is little-endian. Assert against hand-written expected bytes, never
  round-trip-only.
- `progress` is forwarded to Enigma.Core untouched — it reports payload bytes processed. Do not add
  header bytes to it; the XML docs promise they are excluded.
- Never dispose a caller's stream.
- Large-payload tests should stream from a generated source rather than materializing 8 MiB arrays
  where avoidable, so the tests themselves demonstrate the streaming property.
