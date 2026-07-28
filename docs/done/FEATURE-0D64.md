# FEATURE-0D64 — Selectable RSA-OAEP hash for method `0x03` — DONE

**Branch:** `feature/feature-0d64-rsa-oaep-hash`
**Plan:** `docs/plan/FEATURE-0D64.md`

## Summary

Method `0x03` now carries its **RSA-OAEP padding hash in the header**, selectable by the caller at encrypt
time and read from the container at decrypt time. SHA-256 (the default), SHA-384 and SHA-512 are accepted;
SHA-1 is rejected in both directions and its wire byte `0x01` is reserved.

The hash byte sits at **offset 5**, where ML-KEM and the hybrid already put their parameter set, so the RSA
header grew from `37 + N` to `38 + N` and every offset past 4 moved: nonce 5 → 6, wrapped-key length
17 → 18, wrapped key 21 → 22, key-confirmation tag `21 + N` → `22 + N`. **Format version stays `0x10`** —
nothing has shipped, so no bump was owed, and the whole cost was regenerating fixtures. The two public-key
shapes are now structurally identical at `38 + N`, which inverted the premise of two `FormatLayoutTests`
assertions rather than merely their numbers.

The spec moved first, as the plan required: `docs/format.md` §2.4, §3.3, §4, §6, §7.1, §7.2, §9 and §10
were updated before any code. Two claims in it made the *same* "only algorithmic degree of freedom"
statement (§2.4 and §4's closing paragraph) and were qualified together, so the spec does not contradict
itself two sections before the table it points at.

**§4's `RSA key wrapping` row was narrowed, not deleted.** By the time this item ran, that row covered
methods `0x03` *and* `0x05`. It is now normative for the hybrid alone — whose wrap stays fixed at
OAEP-SHA-256, because its data key is a *combination* of two secrets rather than the whole of key transport,
so it carries no compliance argument of its own — while `0x03` points at §3.3. Deleting the row outright
would have left the hybrid's wrapping hash with no normative statement.

One further thing landed that the plan flagged as **pre-existing rather than new**: an RSA public key too
small to wrap a 32-byte data key under the selected hash (RFC 8017 §7.1.1: `k >= 2·hLen + 34`) previously let
Enigma.Core's `CryptographicException` escape `RsaDataEncryptionService` unwrapped and undocumented. It is
now an `ArgumentException` on `publicKeyPem` with the original as `InnerException`, and §9 has a row for it —
**covering the default SHA-256 too**, where the gap was already reachable below a 98-byte modulus. Making the
hash selectable only widened the condition to a commonplace key size (RSA-1024 fails with SHA-384 and
SHA-512), so the fix closes the old gap rather than describing only the new one.

## Files touched

### Created

- `src/Enigma.DataEncryption/Internal/RsaOaepHashWire.cs` — the explicit `RsaOaepHash` ↔ wire-byte mapping,
  modelled on `MLKemParameterSetWire`. `ToWireByte` and `ValidateArgument` reject `Sha1` and undefined
  values with `ArgumentOutOfRangeException`; `FromWireByte` rejects `0x00`, the reserved `0x01` and
  everything from `0x05` up with `DataEncryptionFormatException`, distinguishing *reserved* from *undefined*
  in the message.
- `tests/…/Internal/RsaOaepHashWireTests.cs` — round-trips, the whole-byte-range acceptance sweep, and both
  SHA-1 rejection directions.
- `tests/…/Services/Fixtures/rsa-aes-sha384.bin`, `rsa-aes-sha512.bin` — read-path vectors for the two
  non-default hashes.

### Modified — library

- `Internal/FormatLayout.cs` — new `OaepHashLength` constant (deliberately *not* a reuse of
  `ParameterSetLength`, so each shape's arithmetic still reads on its own), folded into
  `RsaHeaderBaseLength` (37 → 38); remarks list updated.
- `Internal/HeaderWriter.cs` — `WriteRsaHeaderAsync` takes the `RsaOaepHash` and writes its wire byte before
  the nonce.
- `Internal/HeaderReader.cs` — `ReadRsaBodyAsync` resolves offset 5 and populates the hash on both the
  internal and public results.
- `Internal/ParsedHeader.cs` — carries `RsaOaepHash?` for the unwrap.
- `Internal/LimitsValidator.cs` — the wrapped-key-length doc comment's offset (17 → 18).
- `EncryptedDataHeader.cs` — new `RsaOaepHash?` property, populated for `0x03` only; `HeaderLength` doc.
- `EncryptionMethod.cs` — `Rsa`'s summary no longer names a fixed hash.
- `Services/IRsaDataEncryptionService.cs` — `oaepHash` on `EncryptAsync` (after the key, before `progress` —
  where `IMLKemDataEncryptionService` puts `MLKemParameterSet`); type remarks; the key-size interaction; the
  two new exception rows. `DecryptAsync`'s signature is **unchanged**.
- `Services/RsaDataEncryptionService.cs` — validates the hash synchronously, threads it to `EncryptOaep` and
  from `ParsedHeader` to `DecryptOaep`, and gained `WrapDataKey` to translate the too-small-key failure. No
  constructor or field changes.
- `DataEncryptionFileExtensions.cs` — the RSA `EncryptFileAsync` gained the same optional parameter and
  validates it **before either file is opened**. `DecryptFileAsync` is unchanged.
- `Enigma.DataEncryption.csproj` — `<Description>` and `<PackageReleaseNotes>`.

### Modified — tests

`Api/FormatConstantsTests.cs`, `Internal/FormatLayoutTests.cs`, `FormatTestData.cs`, `HeaderShape.cs`,
`HeaderGoldenBytesTests.cs`, `HeaderRoundTripTests.cs`, `HeaderTruncationTests.cs`,
`HeaderValidationTests.cs`, `Services/RsaTestData.cs`, `RsaKeyFixture.cs`, `RsaRoundTripTests.cs`,
`RsaFailureTests.cs`, `RsaArgumentValidationTests.cs`, `RsaGoldenVectorTests.cs`, `RsaCancellationTests.cs`,
`RsaKeyMaterialClearingTests.cs`, `ContainerMethodHarness.cs`, `MalformedContainerSweepTests.cs`,
`EncryptedDataInspectorTests.cs`, `DataEncryptionFileExtensionsTests.cs`, `GoldenVectorInventoryTests.cs`,
`ServiceThreadSafetyTests.cs`, `DependencyInjection/ServiceCollectionExtensionsTests.cs`, and the two
regenerated fixtures `rsa-aes.bin` / `rsa-twofish.bin`.

`RsaTestData.cs` was, as the plan predicted, the file the change was designed to break: it transcribes the
§3.3 layout for every RSA suite, and every offset in it moved.

### Modified — docs

`docs/format.md`, `docs/guides/rsa.md`, `header-inspection.md`, `file-operations.md`, `hybrid.md`,
`README.md`, `RELEASENOTES.md`, `docs/roadmap.md`, `docs/plan/FEATURE-0D64.md`.

`CLAUDE.md` was refreshed in the freshness sweep, in six places: *Current state*'s opening (one item now
blocks the release, not two), the `PHASE03` bullet, the sweep-size figure, the test count, a new paragraph
describing what this item changed, the *Architecture* caveat paragraph (which described `0D64` as a future
item and is now a statement of the shipped design, including why `0x05` deliberately did not follow),
the method table's RSA row, *Project layout*'s new `RsaOaepHashWire.cs` entry, and the *Dev workflow* chain.

## Deviations & follow-ups

- **The fixture generator was rebuilt in the session scratchpad and is not committed**, matching what
  `docs/done/FEATURE-11B6-PHASE03.md` records for the original. It lays the §3.3 header out by hand, takes
  the OAEP wrap and the Twofish-GCM payload from Enigma.Core (the platform has neither) and the AES-GCM
  payload and key-confirmation tag from `AesGcm` / `HMACSHA256`, and **self-verifies each container before
  writing it** — unwrap, re-derive the tag, decrypt the payload. All four fixtures came out at 355 bytes
  (354 → 355 as the plan predicted).
- **The weak RSA key pairs are generated, not committed.** `RsaKeyFixture` gained a 1024-bit and a 512-bit
  pair rather than PEM fixtures, so no usable-looking weak key sits in the repository. Small moduli are the
  cheap ones to generate, so this cost nothing measurable.
- **Two `FormatLayoutTests` assertions changed premise, not just numbers.**
  `TheMLKemBaseIsOneByteLongerThanTheRsaBase` became `TheTwoPublicKeyBasesAreTheSameLength` (an equality),
  and `AnRsaHeaderIs37PlusTheWrappedKeyLength` was renamed. Both remarks were rewritten rather than left
  describing the old shape, and one new assertion pins that both offset-5 selectors are one byte.
- **One fix outside the plan's list, in a table the plan sent me to.**
  `docs/guides/header-inspection.md`'s property table still said `WrappedKeyLength`, `EncapsulationLength`
  and `MLKemParameterSet` were populated for `Rsa`/`MLKem` only — drift left by `FEATURE-5A30`, which made
  all three apply to `Hybrid` as well (the guide's own code sample below it already read them for the
  hybrid). Adding a correct `RsaOaepHash` row beside three wrong ones would have been worse than fixing
  them, so the column was corrected and the `HeaderLength` formula list completed with the hybrid's.
- **The plan's CLAUDE.md note cited "~16,150 tests"**; that figure had already moved to ~26,996 by
  `FEATURE-5A30`. The real number after this item is **28,272** across both test TFMs (14,136 each), and the
  malformed-input sweep is now **4,724 cases per TFM** — the plan's "~2,600" was itself pre-`5A30`.
- **No `DataEncryptionLimits` change**, as planned: `MaxWrappedKeyLength` still bounds `N`, which does not
  depend on the hash. **No DI change**, as planned.
- **No line-ending (CRLF) issues observed** in any file touched.

## Build/test evidence

- `dotnet build Enigma.DataEncryption.slnx -c Release` — **succeeded, 0 warnings, 0 errors** (warnings are
  errors in this repo, so this is also the analyzer and XML-doc gate).
- `dotnet test --solution Enigma.DataEncryption.slnx -c Release` — **28,272 passed, 0 failed, 0 skipped**
  across `net8.0` and `net10.0`.
- Library coverage **98.02% line / 92.09% branch** (`--coverage`, cobertura, `Enigma.DataEncryption`
  package), holding the pre-change level.
- `Api/BouncyCastleIsolationTests`, `Api/InternalSurfaceIsolationTests` and `Api/FormatConstantsTests` all
  green: `RsaOaepHash` is an Enigma.Core type on the public surface, not a BouncyCastle one, and
  `RsaOaepHashWire` stays internal.
- **Guide snippets re-verified by compilation.** There is no permanent doc-sample test project, so a
  throwaway scratchpad project referencing the built library compiled every changed snippet — the new
  hash-selection section, the too-small-key catch block, the shifted positional `progress`/`token` call, the
  printed `EncryptAsync` signature, the inspector's RSA branch and the two file-path rows. Zero warnings,
  zero errors.

## Acceptance criteria

| # | Criterion | Evidence |
|---|-----------|----------|
| 1 | Spec updated first; no self-contradiction | §2.4, §3.3, §4, §6, §7.1, §7.2, §9, §10 committed before code; §2.4 and §4's closing paragraph qualified together |
| 2 | 4 ciphers × 3 hashes round-trip; header still full AAD; `kcTag` construction unchanged | `RsaRoundTripTests.RoundTripsEveryCipherUnderEveryOaepHash` (12 cases × 2 TFMs), `TheHashByteIsCoveredByTheAssociatedData`, `RoundTripsAtRsa3072UnderEveryOaepHash` |
| 3 | `Sha1` rejected as an argument; `0x01` reserved in §10 and rejected by the reader | `RsaOaepHashWireTests`, `RsaArgumentValidationTests.Encrypt_Sha1_Throws`, `HeaderValidationTests.TheReservedSha1HashByteIsRejectedAsReserved`, `HeaderGoldenBytesTests.RsaOaepHashByte_IsNeverTheReservedSha1Value` |
| 4 | Too-small key → `ArgumentException` on `publicKeyPem` with cause inside, **default hash included**; §9 documents it | `RsaFailureTests.ATooSmallPublicKeyIsAnArgumentErrorOnThePublicKey`, `…UnderTheDefaultHashToo`, `RsaTenTwentyFourStillWorksUnderTheDefaultHash`, `ATooSmallPublicKeyWritesNothing` |
| 5 | Inspector reports it; `EncryptFileAsync` accepts and validates before opening either file; `DecryptFileAsync` unchanged; prose and XML docs updated | `EncryptedDataInspectorTests.TheOaepHashIsReported`, `RsaArgumentValidationTests.EncryptFile_RejectsTheHashBeforeOpeningEitherFile`, `DataEncryptionFileExtensionsTests.TheRsaWrapperHonoursTheOaepHash`; docs list above |
| 6 | Fixtures regenerated; inventory matches; 354 → 355; sweep covers the new shape, still only two exception types | `GoldenVectorInventoryTests` (4 RSA container rows, hash byte asserted per row), `RsaGoldenVectorTests` (355 asserted), `MalformedContainerSweepTests.AnEditedRsaOaepHashByteIsAContainerError` (255 cases) |
| 7 | Isolation and constants suites green | Part of the passing run |
| 8 | Zero-warning Release build; full suite green on both TFMs | Above |
