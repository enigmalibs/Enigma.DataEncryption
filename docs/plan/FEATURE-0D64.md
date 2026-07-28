# FEATURE-0D64 — Selectable RSA-OAEP hash for method `0x03`

**Status:** DONE
**Type:** FEATURE (single-phase)
**Suggested branch:** `feature/feature-0d64-rsa-oaep-hash`
**Depends on:** FEATURE-11B6 (complete), FEATURE-5A30 (build it first — see *Ordering* below)

## Why this exists

The predecessor, `Enigma.Cryptography.DataEncryption`, wrapped its data key with
`PublicKeyServiceFactory.CreateRsaService()` — a `Pkcs1Encoding(new RsaEngine())`, i.e. **RSAES-PKCS#1
v1.5**. This library wraps with **RSAES-OAEP-SHA-256**, pinned as a fixed, non-selectable parameter by
`docs/format.md` §4. That difference is deliberate and stays: PKCS#1 v1.5 encryption padding is
deprecated (the Bleichenbacher / Marvin padding-oracle class), and `FEATURE-136E` is `ABANDONED`, so
there are no legacy containers to read either. **PKCS#1 v1.5 is not being brought back.**

What *is* worth adding is the axis one step up: which **hash** OAEP uses. Enigma.Core already offers
`RsaOaepHash.Sha1 | Sha256 | Sha384 | Sha512` on `EncryptOaep`/`DecryptOaep`, and a caller under a
policy that mandates SHA-384 or SHA-512 for key transport currently has no way to comply.

**This does not contradict §4's "an attacker-editable algorithm selector is a downgrade lever"
argument — it lands inside the one exception §4 already carves out.** §4 closes by admitting the cipher
byte precisely because "all four options are equivalent 256-bit AEADs and no choice is a downgrade of
another". The same holds for the OAEP hash: OAEP's security proof needs no collision resistance from
its hash, so SHA-256, SHA-384 and SHA-512 are equivalent choices here rather than a ladder. SHA-1 is
excluded anyway (below), so the field offers nothing to downgrade *to*.

**The window for this is now.** v1.0.0 is prepared but **not published**, so no container exists
outside this repository: the `0x03` header shape can still change with **no format-version bump** and
no legacy-reader burden. The entire cost is regenerating the committed RSA fixtures and golden vectors.
After the release the same change would cost a version bump or a second method byte.

## Objective

Carry the OAEP hash in the method `0x03` header, selectable by the caller at encrypt time and read from
the header at decrypt time. Accept **SHA-256 (default), SHA-384 and SHA-512**. Reject SHA-1 and reserve
its wire byte.

## Scope decisions already settled

These were decided during planning. Do not re-litigate them mid-build; if one turns out to be wrong,
stop and reconcile `docs/format.md` first.

1. **SHA-1 is rejected**, not merely discouraged. Wire byte `0x01` is *reserved* for it in §10 so it can
   be enabled later as a pure un-reservation. The justification for selectability at all is
   policy/compliance (SHA-384/512 mandates); nothing mandates OAEP-SHA-1, and because no external
   system ever unwraps these keys, the legacy-interop argument that usually rescues SHA-1 does not
   apply here.
2. **The hash byte goes at offset 5**, where ML-KEM (§3.4) already puts its algorithm-selector byte, so
   the two public-key methods stay structurally identical (both `38 + N`).
3. **Wire values are 1-based and aligned with the `RsaOaepHash` declaration order** — `0x01` SHA-1
   (reserved), `0x02` SHA-256, `0x03` SHA-384, `0x04` SHA-512. `0x00` is never valid, so a zero-filled
   header cannot parse — the same rationale §3.4 gives for the parameter-set byte. Aligning with the
   enum's order (rather than renumbering the accepted set to start at `0x01`) is what keeps enabling
   SHA-1 later a one-line change.
4. **Enigma.Core's `RsaOaepHash` is reused**, not mirrored by a library-local enum — the same rule that
   makes `MLKemParameterSet` appear on this library's surface.
5. **Format version stays `0x10`.** Nothing has shipped, so no bump is owed.
6. **No predecessor parity sweep.** This library is a clean break: the predecessor's `Tools` facade and
   its `IKeyGenerationService` / `KeyAlgorithm` / `RsaKeySize` have no counterpart here and are not
   being added — key generation is Enigma.Core's job (`GenerateRsaKeyPair`). Recorded so the decision
   is not mistaken for an oversight later.

## Ordering

Build **after `FEATURE-5A30`**. The hybrid method extends `EncryptedDataHeader`, the header
reader/writer, `FormatLayout`, the RSA test helpers and the malformed-input sweep — the same files this
item touches — so the reverse order means two passes over each. (`DataEncryptionLimits` and the inspector
implementation are extended by `5A30` alone; this item leaves both unchanged.) There is no technical
dependency in the other direction — this item touches only method `0x03` — but `FEATURE-F612` (the audit)
must see both finished, so the row order is `5A30` → `0D64` → `F612`.

**One consequence of that order is easy to miss:** by the time this item runs, §4's fixed-parameter row
for RSA wrapping covers method `0x05` too. See the §4 bullet under *Documentation* — narrowing that row
is not optional bookkeeping.

## Design

### New method `0x03` header — 38 + `N` bytes

| Offset | Size | Field |
|---|---|---|
| 0 | 5 | Common prefix (§2), method `0x03` |
| **5** | **1** | **OAEP hash — `0x02` SHA-256 · `0x03` SHA-384 · `0x04` SHA-512** (`0x01` reserved for SHA-1; `0x00` invalid) |
| 6 | 12 | GCM nonce |
| 18 | 4 | Wrapped-key length `N` (`Int32` LE) |
| 22 | `N` | Wrapped data key — RSAES-OAEP with the selected hash, over the 32-byte data key |
| 22 + `N` | 16 | Key-confirmation tag (§6) |
| **38 + `N`** | var | GCM payload |

`N` still equals the RSA modulus size in bytes, independent of the hash.

### Internal changes (`src/Enigma.DataEncryption/Internal/`)

- **New `RsaOaepHashWire.cs`** — modelled on `MLKemParameterSetWire.cs`: `ToWireByte` (mapping only
  `Sha256`/`Sha384`/`Sha512`, and throwing `ArgumentOutOfRangeException` for `Sha1` and undefined
  values, so **no writer can emit the reserved `0x01`** — `MLKemParameterSetWire.ToWireByte` sets that
  precedent), `FromWireByte` (rejecting `0x00`, the reserved `0x01`, and anything `>= 0x05` with
  `DataEncryptionFormatException`) and `ValidateArgument` (rejecting `Sha1` and undefined values with
  `ArgumentOutOfRangeException`). **Explicit mapping in both directions — never a cast**, the same rule
  the ML-KEM parameter set carries.
- **`FormatLayout.cs`** — add a dedicated 1-byte constant for the selector (e.g. `OaepHashLength`)
  rather than reusing `ParameterSetLength`, so each method's layout still reads independently, and add
  it to `RsaHeaderBaseLength` (37 → 38).
- **`HeaderWriter.WriteRsaHeaderAsync`** — takes the `RsaOaepHash` and writes its wire byte at offset
  5. It still returns the complete header bytes, so the AAD and `kcTag` inputs need no special handling.
- **`HeaderReader`** — reads and validates the byte for method `0x03`, exposing the resolved hash.
- **`ParsedHeader.cs`** — carry the resolved `RsaOaepHash` for the unwrap (alongside the existing
  method-specific key material).

### Public surface

```csharp
// IRsaDataEncryptionService — selector after the key, before progress: exactly where
// IMLKemDataEncryptionService puts MLKemParameterSet.
Task EncryptAsync(
    Stream input,
    Stream output,
    Cipher cipher,
    string publicKeyPem,
    RsaOaepHash oaepHash = RsaOaepHash.Sha256,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

- `DecryptAsync` is **unchanged** — the hash comes from the header, never from the caller.
- `DataEncryptionFileExtensions.EncryptFileAsync` (the RSA overload) gains the same optional parameter
  and calls `RsaOaepHashWire.ValidateArgument` **before either file is opened**, mirroring how the
  ML-KEM extension validates its parameter set. That ordering is load-bearing: the output is
  `FileMode.Create`, so validating later would truncate a caller's existing file.
  **The RSA `DecryptFileAsync` extension is unchanged**, exactly as the ML-KEM `DecryptFileAsync`
  deliberately omits `parameterSet` — the selector is read from the header, so it is not a parameter
  there. Adding it would be a permanent v1.0.0 API mistake.
- **In-code XML documentation moves with the layout.** These are shipped documentation and none of them
  is compile-checked, so they will silently go stale unless listed: `EncryptedDataHeader.HeaderLength`
  (`EncryptedDataHeader.cs:46`, "37 + `WrappedKeyLength` for RSA"), `IRsaDataEncryptionService`'s type
  remarks (`:10` "under **RSAES-OAEP with SHA-256**" and `:14` "a (37 + `N`)-byte plaintext header"),
  `EncryptionMethod.Rsa` (`EncryptionMethod.cs:34`, "RSAES-OAEP (SHA-256) key transport"),
  `HeaderWriter.WriteRsaHeaderAsync` (`:100`, "37 + `N` bytes"), `FormatLayout`'s remarks (`:11` and
  `:56`, the "53 / 61 / 37 + N / 38 + N" list) and **`LimitsValidator.cs:46`** ("The value read from
  header offset 17" → 18). The *new* `oaepHash` parameters and the new `EncryptedDataHeader` property
  are build-enforced by contrast (`GenerateDocumentationFile` + `TreatWarningsAsErrors`: CS1573/CS1591),
  so they cannot be forgotten.
- `EncryptedDataHeader` gains `public RsaOaepHash? RsaOaepHash { get; init; }` — populated for method
  `0x03` only, same shape as the existing `MLKemParameterSet?` property (property name matching the
  type name has precedent there).
- `DataEncryptionLimits` — **unchanged**. `MaxWrappedKeyLength` still bounds `N`.
- `AddEnigmaDataEncryption()` — **unchanged**.
- `RsaDataEncryptionService` threads the hash from `EncryptAsync` to `EncryptOaep`, and from
  `ParsedHeader` to `DecryptOaep`. No constructor or field changes.

### Error handling

| Condition | Exception |
|---|---|
| `oaepHash` is `Sha1`, or not a defined `RsaOaepHash` value | `ArgumentOutOfRangeException` on `oaepHash` |
| Header hash byte is `0x00`, the reserved `0x01`, or `>= 0x05` | `DataEncryptionFormatException` |
| **RSA OAEP wrap fails — public key too small for the chosen hash** (`CryptographicException`) | **`ArgumentException` on `publicKeyPem`, wrapping it** |

The third row is new to §9, which currently has no RSA *wrap*-failure row at all.

**The condition is already reachable today — this feature widens it, it does not create it.** A 32-byte
data key needs `k >= 2·hLen + 34` (RFC 8017 §7.1.1: `mLen <= k - 2hLen - 2`), so the current fixed
SHA-256 already fails for any modulus below 98 bytes (784 bits), and
`RsaDataEncryptionService.EncryptCoreAsync` does not catch it — Enigma.Core's `CryptographicException`
escapes unwrapped and undocumented right now, and Enigma.Core's `GenerateRsaKeyPair` accepts any
positive key size. With the hash selectable the same failure arrives at a commonplace key size:
**OAEP-SHA-384 needs a ≥1040-bit modulus (130 bytes) and OAEP-SHA-512 a ≥1296-bit one (162 bytes), so
RSA-1024, at 128 bytes, fails with both.** The new §9 row therefore covers **the default hash as well**,
closing the pre-existing gap rather than describing only the new one.

Enigma.Core translates the failure into `CryptographicException` ("The data may be too large for the
key…") and exposes **no modulus-size accessor**, so pre-validating would mean parsing the modulus here —
which this library has no way to do: it takes no direct BouncyCastle dependency (only Enigma.Core and
the DI abstractions), and `netstandard2.0` offers no PEM/RSA parser either. **Translation is therefore
the only available option**, and `ArgumentException` on `publicKeyPem` is the right target: it is
exactly the rule §9
already applies to ML-KEM `Encapsulate` (the encrypt side takes the caller's public key and nothing
else, so a failure can only concern that key), and it keeps §9's closing claim — "Enigma.Core's RSA
path already reports an unusable public key that way, so the two methods agree on the encrypt side" —
true rather than merely almost true. The original exception is preserved as `InnerException`.

An **edited** hash byte on an otherwise valid container needs no new rule: the reader uses the byte to
choose the unwrap, so a wrong value makes OAEP unwrap fail, which §9 already maps to
`DataDecryptionException` wrapping the cause. Assert it; do not special-case it.

## Documentation

`docs/format.md` — the spec moves **first**, before implementation:

- **§3.3** — new field table (above), and rewrite the closing paragraph: the "no public-key fingerprint
  field" rationale stays, and the OAEP hash is now documented as a header field with its accepted and
  reserved values.
- **§4** — the `RSA key wrapping | RSAES-OAEP, SHA-256` row is **narrowed, not removed**. Because this
  item builds *after* `FEATURE-5A30`, that row by then covers **two** methods, and only `0x03` becomes
  selectable: the hybrid `0x05` keeps a fixed OAEP-SHA-256 wrap (see `docs/plan/FEATURE-5A30.md`).
  Deleting the row outright would leave the hybrid's wrapping hash with no normative statement, under a
  preamble that still reads "None of them is stored in the header, and none is selectable". So: retitle
  it for the hybrid alone and point method `0x03` at §3.3. Then extend §4's closing paragraph so the
  cipher byte is no longer described as "the only algorithmic field a container carries", carrying the
  same "no choice is a downgrade of another" argument over to the OAEP hash.
- **§2.4** — makes the *same* claim in different words: "it is the only algorithmic degree of freedom
  the format offers (see §4)". It must be qualified exactly as §4's closing paragraph is, or the spec
  contradicts itself two sections before the table it points at.
- **§6** — the `headerBytesBeforeTag` bullet: `21 + N` for RSA becomes **`22 + N`**.
- **§7.1** step 3 — RSA wraps `K` under the recipient's public key **with the selected OAEP hash**.
- **§7.2** step 2 — the method-body fields include the OAEP-hash byte for RSA, as they already do the
  parameter-set byte for ML-KEM.
- **§9** — the new wrap-failure row, plus the invalid/reserved hash-byte row.
- **§10** — reserved values gains the OAEP-hash byte: `0x01` reserved for OAEP-SHA-1, `0x05`–`0xFF`
  undefined.

Then the guides and packaging prose:

- **`docs/guides/rsa.md`** — a hash-selection section: what the default is, why SHA-1 is rejected, and
  the key-size interaction (`k >= 2·hLen + 34`; RSA-2048 and up are unaffected; RSA-1024 fails with
  SHA-384 and SHA-512, and what exception that produces). **Plus five existing passages the change
  falsifies**, which must be rewritten rather than left beside the new section: the intro at `:9`
  ("wraps *that* under **RSAES-OAEP with SHA-256**"), the "There are no algorithm choices to make on the
  RSA side … The only degree of freedom is `cipher`" paragraph at `:29`, the printed `EncryptAsync`
  signature block at `:52-59`, the positional snippet at `:274-275` (which passes `progress, cts.Token`
  in the slots the new parameter shifts, so it stops compiling), and the header arithmetic at
  `:289-290` ("37 + 256 … 37 + 384 … 37 + 512" → 38 + each). Every snippet re-verified against the real
  public surface of both this library and Enigma.Core — there is no doc-sample test project, so that
  check is a per-dev obligation.
- **`docs/guides/header-inspection.md`** — the property table gains the `RsaOaepHash?` row; the
  `HeaderLength` formula for RSA becomes `38 + WrappedKeyLength`; the RSA branch of the sample can
  report the hash.
- **`docs/guides/file-operations.md`** — the signature table row for `IRsaDataEncryptionService`
  gains the optional `RsaOaepHash oaepHash`.
- **`docs/guides/README.md`** — only if its blurb names the fixed hash.
- **`README.md`** *Features* — RSA-OAEP now says SHA-256/384/512 (prose-only pointers to the guides;
  no clickable `docs/…` link, since the README is packed and the guides are not).
- **`RELEASENOTES.md`** (both mentions), the csproj's **`PackageReleaseNotes`** *and* the csproj's
  **`<Description>`** — **all three** name "RSAES-OAEP-SHA256" and are updated together. `<Description>`
  is the text nuget.org renders on the package page, so leaving it would publish a claim the format no
  longer makes; the notes and `PackageReleaseNotes` are duplicated prose kept in step only by a csproj
  comment.
- **`CLAUDE.md`** — three places: *Architecture* (**delete** the "fixed at OAEP-SHA-256 today … becomes
  a header field in `FEATURE-0D64`" paragraph and its §4 caveat — once this lands it is no longer a
  caveat but the state of things), *Project layout* (add `RsaOaepHashWire.cs`), and **Current state**
  (the "~16,150 tests" and "~2,600 corrupted containers per TFM" figures both move — 4 ciphers × 3
  hashes of round-trips, a per-value hash-byte sweep and new fixtures all add tests). The freshness
  sweep will surface these; they are listed so they are not treated as optional.

## Test strategy

`tests/Enigma.DataEncryption.UnitTests/`, both test TFMs (`net8.0`, `net10.0`):

> **Start here: `Services/RsaTestData.cs` is the file this change is designed to break.** It transcribes
> the §3.3 layout for *every* RSA service suite — `NonceOffset = 5` (`:25`) → 6,
> `WrappedKeyLengthOffset = 17` (`:28`) → 18, `WrappedKeyOffset = 21` (`:31`) → 22, the tag-offset helper
> (`:51-52`) 21 + `N` → 22 + `N`, the "37 + 256" doc comments (`:36`, `:44`) → 38 + — and its own remark
> says the offsets "are written out rather than computed so that a layout change in `FormatLayout` shows
> up here as a failing test". It also needs a hash parameter on `WrapOaep`/`UnwrapOaep` (`:181`, `:190`,
> both pinned to `RsaOaepHash.Sha256`) and a new argument in `BuildHeaderAsync`'s call to
> `HeaderWriter.WriteRsaHeaderAsync` (`:159-173`).
>
> **Then fix the positional call sites — these are compile errors, not test failures.** Inserting
> `RsaOaepHash oaepHash` at parameter 5 means the `null` currently passed there for `progress` no longer
> binds (CS1503): `Services/RsaTestData.cs:88-89`, `Services/ServiceThreadSafetyTests.cs:202-203`,
> `Services/RsaKeyMaterialClearingTests.cs:32-33` and `:47-48`,
> `Services/RsaCancellationTests.cs:36-37, :83-84, :100-101, :128`,
> `DependencyInjection/ServiceCollectionExtensionsTests.cs:178`, and
> `Services/ContainerMethodHarness.cs:395-396` (`EncryptAsync`) and `:417-418` (`EncryptFileAsync`).
> None of them changes behaviour; all of them stop the build until updated.

- **`Internal/FormatLayoutTests.cs`, `Api/FormatConstantsTests.cs`** — RSA header base length 37 → 38,
  pinned against §3.3. Note two tests in `FormatLayoutTests` whose *premise* inverts, not just their
  number: `TheMLKemBaseIsOneByteLongerThanTheRsaBase` (`:63`) becomes an equality — the two public-key
  shapes are now structurally identical, so its remark calling the parameter-set byte "the only
  structural difference between the two shapes' fixed parts" must be rewritten — and
  `AnRsaHeaderIs37PlusTheWrappedKeyLength` (`:46`) must be renamed.
- **`Services/ContainerMethodHarness.cs`** — the sweep's per-method shape data lives here, not in
  `MalformedContainerSweepTests.cs`: the RSA header length (`:103`, `:381`) and the RSA tamper-field
  offset the sweep edits (`:385`, `WrappedKeyLengthOffset`) both move with the layout.
- **New `Internal/RsaOaepHashWireTests.cs`** — round-trip for the three accepted values; `0x00`, the
  reserved `0x01` and `0x05`–`0xFF` rejected as `DataEncryptionFormatException`; `Sha1` and undefined
  enum values rejected as `ArgumentOutOfRangeException`. Mirror `MLKemParameterSetWireTests.cs`.
- **`Internal/HeaderRoundTripTests.cs`, `HeaderGoldenBytesTests.cs`, `HeaderTruncationTests.cs`,
  `HeaderValidationTests.cs`, `HeaderShape.cs`, `FormatTestData.cs`** — the new offsets and the new
  byte; the truncation sweep must cover truncation *at* offset 5.
- **`Services/RsaRoundTripTests.cs`** — 4 ciphers × 3 hashes, RSA-2048 and RSA-3072.
- **`Services/RsaGoldenVectorTests.cs`** — byte-exact expectations per hash, with the wrapped key the
  documented exception (OAEP randomness), as the existing suite already words it.
- **`Services/RsaFailureTests.cs`** — tamper coverage on the new byte (edited value → the OAEP-unwrap
  path → `DataDecryptionException`); wrong key unchanged. Its hard-coded `21 + …` tamper offsets
  (`:53-55`) move with `RsaTestData`'s.
- **`Services/RsaArgumentValidationTests.cs`** — `Sha1` and undefined `oaepHash` rejected, on both the
  service and the file-path extension, and **before either file is opened** (assert the output file is
  not created).
- **New coverage for the too-small key** — RSA-1024 with SHA-384 and SHA-512 surfaces as
  `ArgumentException` on `publicKeyPem` with the `CryptographicException` preserved as
  `InnerException`, and a sub-784-bit key does the same **under the default SHA-256** (the pre-existing
  gap). Generate the weak pairs via Enigma.Core rather than committing weak PEMs — preferably by adding
  them to the generate-once `Services/RsaKeyFixture.cs` (which already generates its keys at runtime and
  is where the suite pays for RSA key generation once), not as a per-test generation.
- **`Services/EncryptedDataInspectorTests.cs`** — the inspector reports the hash for `0x03` and leaves
  the property `null` for the other three methods.
- **`Services/MalformedContainerSweepTests.cs`** — the generated sweep extended to the new shape, still
  admitting **only** the two container exception types and never an indexing, allocation or unwrapped
  Enigma.Core failure.
- **`Services/DataEncryptionFileExtensionsTests.cs`** — the new optional parameter, including the
  close-before-delete cleanup path.
- **Fixtures** — `Services/Fixtures/rsa-aes.bin` and `rsa-twofish.bin` **regenerated** (every offset
  past 4 has moved, and the RSA-2048 container grows 354 → 355 bytes); new fixtures for the SHA-384 and
  SHA-512 read paths; the PEM fixtures are unaffected; `Services/GoldenVectorInventoryTests.cs` updated
  so the executable inventory still matches what is committed.
  **There is no committed generator to run** — `docs/done/FEATURE-11B6-PHASE03.md` records that a
  *one-off* generator built these containers and it was never committed. Rebuild it in the session
  scratchpad, laying the header out from §3.3 by hand, taking the OAEP wrap from Enigma.Core and the
  AES-GCM payload from the platform's `AesGcm`. **Expect every RSA fixture assertion to be red between
  the reader change and the regeneration** — the byte now at offset 5 is the old nonce's first byte, and
  a `0x00` there is exactly what the new reader rejects.
- **Unchanged but must stay green** — `Api/BouncyCastleIsolationTests.cs` and
  `Api/InternalSurfaceIsolationTests.cs`. (`ServiceThreadSafetyTests`, `RsaKeyMaterialClearingTests`,
  `RsaCancellationTests` and the DI suite are *not* unchanged — see the positional call sites above.)

Golden vectors must continue to be computed **outside this library** (the platform's `AesGcm`, Python's
`hashlib`/`hmac`) so they pin the format rather than the implementation — with the two documented
exceptions the suite already carries and states: the OAEP wrap itself comes from Enigma.Core (OAEP
randomness makes it unpinnable anyway), and the Twofish payload stays a **regression** vector, because
no Twofish-GCM implementation exists here outside BouncyCastle.

## Acceptance criteria

1. `docs/format.md` §2.4, §3.3, §4, §6, §7.1, §7.2, §9 and §10 are updated **before** implementation;
   code and spec agree on every offset, length and constant, **and the spec does not contradict itself**
   (§2.4 and §4 make the same "only algorithmic freedom" claim and must be qualified together).
2. Round-trip green for all 4 ciphers × 3 hashes on both test TFMs; the complete header is still passed
   as GCM AAD and the key-confirmation tag is unchanged in construction.
3. `RsaOaepHash.Sha1` is rejected as an argument with `ArgumentOutOfRangeException`; wire byte `0x01`
   is reserved in §10 and rejected by the reader with `DataEncryptionFormatException`.
4. A public key too small for the chosen hash produces `ArgumentException` on `publicKeyPem` with the
   `CryptographicException` preserved as `InnerException` — **for the default SHA-256 as well as the two
   new hashes** — and §9 documents it.
5. The inspector reports the hash; the RSA **`EncryptFileAsync`** extension accepts it and validates it
   before either file is opened, while **`DecryptFileAsync` is unchanged** (the hash comes from the
   header); `docs/guides/rsa.md`, `header-inspection.md`, `file-operations.md`, `README.md`,
   `RELEASENOTES.md`, `PackageReleaseNotes` and the csproj `<Description>` are updated, along with the
   in-code XML docs listed under *Public surface*. DI needs no change.
6. All committed RSA container fixtures are regenerated — with the scratchpad generator rebuilt, since
   none is committed — and `GoldenVectorInventoryTests` matches the committed set, including the RSA-2048
   container's 354 → 355-byte length; the malformed-input sweep covers the new shape and still admits
   only the two container exception types.
7. `BouncyCastleIsolationTests`, `InternalSurfaceIsolationTests` and `FormatConstantsTests` are green.
8. Zero-warning Release build (`dotnet build Enigma.DataEncryption.slnx -c Release`) and the full suite
   green (`dotnet test --solution Enigma.DataEncryption.slnx -c Release`) on both test TFMs.

## If this is dropped

Mark the row `ABANDONED` with a reason, and — because the decision only makes sense read together with
the spec — leave §4's fixed-parameter row for RSA wrapping, and §2.4's "only algorithmic degree of
freedom" sentence, exactly as they are. Nothing else needs reverting, since the item is planned to move
the spec first.

One finding surfaced while planning is **independent of this item and survives its abandonment**: today,
an RSA public key with a modulus below 98 bytes makes the fixed OAEP-SHA-256 wrap throw, and
`RsaDataEncryptionService` lets Enigma.Core's `CryptographicException` escape unwrapped and undocumented
(§9 has no RSA wrap-failure row). If this item is dropped, that gap should be raised as its own `BUG`
item rather than disappearing with it.
