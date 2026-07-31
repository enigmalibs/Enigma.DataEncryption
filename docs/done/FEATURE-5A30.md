# FEATURE-5A30 — True hybrid RSA + ML-KEM method `0x05` — DONE

**Branch:** `feature/feature-5a30-hybrid`
**Plan:** `docs/plan/FEATURE-5A30.md`
**Spec:** `docs/format.md` §2.2, §3.5, §3.5.1, §3.5.2, §4, §6.3, §7, §8, §9, §10

## Summary

Method `0x05` is implemented. The library now has a **fifth encryption method** — the only one taking two
credentials — that transports a 32-byte secret under an RSA public key with RSAES-OAEP-SHA256, encapsulates a
second secret against an ML-KEM public key, and **combines both** into the data key, so a container stays
secure as long as *either* primitive holds. Reserved method byte `0x05` was claimed with no format-version
bump, which is the reservation from `FEATURE-00E7` working exactly as intended.

**The combiner was settled with the maintainer before implementation**, per the plan's instruction that this
was the one construction deserving review first. Two candidates were put up:

| Candidate | Chosen |
|---|---|
| Split-key XOR of two domain-separated HMAC-SHA256 PRFs, one keyed by each secret | ✔ |
| HKDF-Extract-then-Expand over the concatenated secrets (the plan's sketch) | ✘ |

The split-key form was chosen and written into `docs/format.md` §3.5.1 **before** any code, satisfying
acceptance criterion 1. The plan's own sketch was the runner-up, and §3.5.2 records why it lost:

```
T    = LE32(N) ‖ wrappedRsaSecret ‖ LE32(M) ‖ encapsulation

Krsa = HMAC-SHA256(key: rsaSecret, message: ASCII("Enigma.DataEncryption/hybrid/rsa/v1")   ‖ T)
Kkem = HMAC-SHA256(key: kemSecret, message: ASCII("Enigma.DataEncryption/hybrid/mlkem/v1") ‖ T)

K    = Krsa XOR Kkem
```

Three properties made it the better choice, and each is asserted rather than asserted-in-prose:

- **"Secure if either holds" is a one-line reduction from "HMAC is a PRF"** — the same assumption §6 already
  makes. The HKDF-Extract shape would have needed HMAC's *dual*-PRF property (entropy arriving in the message
  under a public salt), which is standard but strictly stronger than anything else in this format relies on.
- **The two labels differ**, which kills a real degenerate case rather than a theoretical one: with a single
  shared label, `rsaSecret == kemSecret` gives `Krsa == Kkem` and therefore `K == 0` — a container readable by
  anyone holding neither private key. A hostile *sender* can force that, because it encapsulates first, sees
  `kemSecret`, and then chooses what to wrap under RSA.
  `HybridKeyCombinerTests.TwoEqualSecretsDoNotCancelToAnAllZeroDataKey` is that case.
- **`T` is exactly the contiguous header slice from offset 18 to the tag**, so the transcript binding can be
  located in a hex dump rather than trusted. `HeaderGoldenBytesTests.HybridHeader_ContainsTheCombinerTranscriptAsAContiguousSlice`
  holds the two side by side.

The header shape is the plan's, with the second length field where the plan put it:

```
0    2   magic EC DE      18   4   wrapped-secret length N (Int32 LE)
2    1   method 05        22   N   wrapped RSA secret (OAEP-SHA256)
3    1   version 10       22+N 4   encapsulation length M (Int32 LE)
4    1   cipher           26+N M   ML-KEM encapsulation
5    1   ML-KEM param set 26+N+M 16 key-confirmation tag
6   12   nonce            42+N+M var GCM payload
```

1,866 bytes for RSA-2048 + ML-KEM-1024. It is the only shape with two variable-length fields, so every offset
past the first one is a function of `N` — which is why `HybridTestData` exposes those offsets as methods
rather than constants, and why the round-trips sweep RSA-3072 as well as 2048.

## Files touched

### Created — library

| File | What |
|---|---|
| `src/…/Internal/HybridKeyCombiner.cs` | The combiner: transcript builder, two branches, XOR. Intermediates cleared in a `finally`. |
| `src/…/Services/IHybridDataEncryptionService.cs` | The public interface, exactly the plan's signatures. |
| `src/…/Services/HybridDataEncryptionService.cs` | The implementation. Four Enigma.Core factories — one more than any other service. |

### Modified — library

| File | What |
|---|---|
| `src/…/EncryptionMethod.cs` | `Hybrid = 0x05` added; the "reserved" remark became "`0x06`–`0xFF` unassigned". |
| `src/…/EncryptedDataHeader.cs` | `WrappedKeyLength`, `EncapsulationLength` and `MLKemParameterSet` now document that the hybrid populates all three; `HeaderLength` gained its fifth case. |
| `src/…/Internal/FormatLayout.cs` | `HybridHeaderBaseLength` (42), `HybridWrappedSecretLengthOffset` (18) and `HybridEncapsulationLengthOffset(N)`. |
| `src/…/Internal/HeaderWriter.cs` | `WriteHybridHeaderAsync`. |
| `src/…/Internal/HeaderReader.cs` | `ReadHybridBodyAsync`; `0x05` now maps to `Hybrid` instead of throwing "reserved". |
| `src/…/Internal/ParsedHeader.cs` | Doc updates — three fields are now shared between two methods each. |
| `src/…/DataEncryptionFileExtensions.cs` | The hybrid `EncryptFileAsync`/`DecryptFileAsync` pair. Twelve wrappers became fourteen. |
| `src/…/ServiceCollectionExtensions.cs` | `IHybridDataEncryptionService` registered as a singleton via `TryAdd`. |
| `src/…/Enigma.DataEncryption.csproj` | `Description`, `PackageTags` and `PackageReleaseNotes` — the last kept in step with `RELEASENOTES.md` as its csproj comment requires. |

### Created — tests

`Internal/HybridKeyCombinerTests.cs`, `Services/HybridTestData.cs`, `Services/HybridTestDoubles.cs`,
`Services/HybridKeyFixture.cs`, `Services/HybridRoundTripTests.cs`, `Services/HybridFailureTests.cs`,
`Services/HybridArgumentValidationTests.cs`, `Services/HybridCancellationTests.cs`,
`Services/HybridKeyMaterialClearingTests.cs`, `Services/HybridGoldenVectorTests.cs`.

### Created — fixtures

| File | What |
|---|---|
| `Services/Fixtures/hybrid-aes.bin` | 1,927 bytes. RSA-2048 + ML-KEM-1024, AES-256-GCM. |
| `Services/Fixtures/hybrid-twofish.bin` | 1,927 bytes. **The same two ciphertexts** under Twofish-256-GCM. |
| `Services/Fixtures/hybrid-kem-secret.bin` | The 32-byte ML-KEM shared secret both containers' encapsulation yields. |

Both containers deliberately share one wrapped secret and one encapsulation, differing only in cipher byte,
tag and payload — the same arrangement the `mlkem-1024-*` pair uses, and what lets one committed KEM secret
pin both. The RSA half's secret is the documented `00`–`1F`, so with the committed KEM secret the combined
data key is a fixed value the vectors reconstruct from the platform's HMAC. They reuse `rsa-2048-*.pem` and
`mlkem-1024-*.key` rather than adding key fixtures; the inventory rows for those four now say so.

The fixtures were generated by a throwaway `HybridFixtureGenerator` test that built the header from the
**platform's** primitives (`HMACSHA256`, `AesGcm`) per §3.5, taking Enigma.Core only for the RSA wrap, the
KEM, and the Twofish payload — the same practice PHASE02–PHASE04 used. The generator was deleted once the
files were on disk; the suite re-establishes their independence on every run.

### Modified — tests

`Api/FormatConstantsTests.cs`, `Internal/HeaderShape.cs`, `Internal/FormatTestData.cs`,
`Internal/FormatLayoutTests.cs`, `Internal/HeaderRoundTripTests.cs`, `Internal/HeaderGoldenBytesTests.cs`,
`Internal/HeaderTruncationTests.cs`, `Internal/HeaderValidationTests.cs`, `Services/ContainerMethodKind.cs`,
`Services/ContainerMethodHarness.cs`, `Services/GoldenVectorPrimitives.cs`,
`Services/GoldenVectorInventoryTests.cs`, `Services/EncryptedDataInspectorTests.cs`,
`Services/MalformedContainerSweepTests.cs`, `Services/ServiceThreadSafetyTests.cs`,
`Services/DataEncryptionFileExtensionsTests.cs`,
`DependencyInjection/ServiceCollectionExtensionsTests.cs`.

### Documentation

`docs/format.md` (the spec), `docs/guides/hybrid.md` (new, the seventh guide), and
`docs/guides/README.md` · `rsa.md` · `ml-kem.md` · `header-inspection.md` · `file-operations.md` ·
`dependency-injection.md` · `README.md` · `RELEASENOTES.md`.

## The two tests the plan singled out

Acceptance criterion 2 — "both 'one credential wrong' tests pass, proving both inputs contribute" — is met,
but **the plan's framing needed strengthening and this is the one substantive deviation**. The plan said both
cases fail "at the key-confirmation stage". Only one of them does, and the difference matters:

- **Right RSA key, wrong ML-KEM key.** Implicit rejection means the decapsulation *succeeds*, the RSA half
  unwraps correctly, and both ciphertexts are exactly as written — so the transcript is unchanged and the
  *only* difference is `kemSecret`. A combiner that ignored it would let this container decrypt. This is a
  genuine isolation test, and it fails at key confirmation as the plan expected.
  (`HybridFailureTests.TheMLKemSecretContributesToTheDataKey`, all three parameter sets, with a payload
  stream that throws if it is touched.)
- **Wrong RSA key, right ML-KEM key.** This fails at the **OAEP unwrap**, earlier than key confirmation —
  RSAES-OAEP detects a mismatched private key. So it would pass even against a combiner that dropped the RSA
  secret entirely, and on its own it proves less than it appears to.
  (`HybridFailureTests.TheWrongRsaPrivateKeyIsADecryptionError`.)

To get the RSA half the same strength, a third test was added:
`HybridFailureTests.TheRsaSecretContributesToTheDataKey` builds a **hostile-sender** container whose
RSAES-OAEP ciphertext unwraps perfectly to a 32-byte secret but whose tag was sealed under a data key combined
from a *different* RSA secret — transcript byte-identical, one secret different. Nothing rejects anything
until the combined key is checked. `AHeaderSealedUnderAnotherKemSecretIsCaughtByKeyConfirmation` is its
mirror. Together with `HybridKeyCombinerTests`' four input-dependency tests, each input is shown to matter
with everything else held fixed.

## Deviations & follow-ups

1. **`DataEncryptionLimits` was not extended**, though `docs/roadmap.md`'s ordering note predicted it would
   be. The hybrid's two variable-length fields are an RSA wrapped secret and an ML-KEM encapsulation — the
   same two quantities methods `0x03` and `0x04` already bound — so `MaxWrappedKeyLength` and
   `MaxEncapsulationLength` apply unchanged. A third and fourth cap naming the same quantities would let a
   reader be configured to accept a 2 KiB wrapped key from a hybrid container while refusing it from an RSA
   one, which is not a distinction worth being able to express. `docs/format.md` §8 now states this, and
   `HybridFailureTests.TighteningEitherCapRejectsAnOtherwiseValidHeader` pins that both caps are honoured
   independently. The roadmap's ordering rationale is unaffected — it rests on the header reader/writer,
   `FormatLayout`, the RSA test helpers and the malformed sweep, all of which `FEATURE-0D64` still shares.
2. **`EncryptedDataHeader` gained no new property.** The plan said to extend it "with the second length
   property"; both length properties already existed and mean exactly the right thing, so the hybrid
   populates `WrappedKeyLength`, `EncapsulationLength` and `MLKemParameterSet` together and only the XML docs
   changed. `EncryptedDataInspectorTests.TheHybridReportsBothLengthsAndTheParameterSet` asserts all three
   positively, and `PropertiesThatDoNotApplyToTheMethodAreNull` was corrected — the hybrid is the one shape
   for which none of the three is null.
3. **A parameter-name discrepancy is documented rather than fixed.** An unparseable PEM propagates from
   Enigma.Core unwrapped, per §9, so its `ParamName` is Enigma.Core's `publicKeyPem` / `privateKeyPem` rather
   than this method's `rsaPublicKeyPem` / `rsaPrivateKeyPem`. Correcting it would mean catching and
   re-throwing — exactly the wrapping §9 rules out for a credential-supply error. A `null` or empty PEM *is*
   rejected by this library and does carry the parameter's own name. Both behaviours are asserted
   (`AnUnparseableRsaPrivateKeyPemPropagatesUnwrapped`) and both are stated on the interface and in the guide.
   The RSA service never exposed this seam because its own parameter happens to share Enigma.Core's name.
4. **`FormatTestData.AllShapes` was added and the four-shape lists were folded into it.** Several header
   suites enumerated the shapes inline; adding a fifth meant finding every such list. Centralising it means
   the next method does not.
5. **A test of mine over-asserted and was corrected before the run was declared green.** The first version of
   `HeaderValidationTests.AnOutOfRangeHybridEncapsulationLengthIsAFormatError` asserted the field name in the
   message for every out-of-range value; Enigma.Core's own `ReadLengthValueAsync` cap rejects negative and
   over-cap lengths first, with a message that names no field, so only `0` reaches `LimitsValidator`. The
   theory now asserts the type, and `TheHybridsTwoLengthFieldsAreRejectedByName` asserts the names at `0` —
   which is what actually distinguishes the second length field's offset from the first's.
6. **Line endings — recommendation only, no action taken.** Nothing anomalous was observed in the files
   touched; a repository-wide `.gitattributes` `* text=auto eol=lf` rule remains the maintainer's call.
7. **Composition was considered and rejected.** `HybridDataEncryptionService` does not delegate to
   `RsaDataEncryptionService` and `MLKemDataEncryptionService`: those each write a complete container of their
   own method, while the hybrid needs the two primitives' *intermediate* outputs — both secrets and both
   ciphertexts — before a single header byte exists. The two translation helpers are therefore duplicated
   from those services, deliberately and with the reasoning recorded at each.

## Build/test evidence

- **Build:** `dotnet build Enigma.DataEncryption.slnx -c Release` — **succeeded, 0 warnings, 0 errors**
  across all three library TFMs (`netstandard2.0`, `net8.0`, `net10.0`) and both test TFMs.
- **Tests:** `dotnet test --solution Enigma.DataEncryption.slnx -c Release` — **26,996 passed, 0 failed,
  0 skipped** over `net8.0` and `net10.0`. Up from ~16,150: the hybrid adds 176 tests of its own, and the
  cross-cutting sweeps grew because they are generated per method and per header byte — the malformed-input
  sweep alone gains a 1,066-byte header shape to truncate at every offset.
- **Coverage:** the library at **98.0% line / 91.8% branch** on both test TFMs (`--coverage
  --coverage-output-format cobertura`, the `Enigma.DataEncryption` package alone) — slightly up from the
  ~97% / ~91% `FEATURE-11B6` left behind, despite ~1,300 new lines of library code.
- **`BouncyCastleIsolationTests` green** (acceptance criterion 7): the new public surface exposes only
  `Stream`, `Cipher`, `string`, `byte[]`, `MLKemParameterSet`, `char[]`, `DataEncryptionLimits`,
  `IProgress<int>` and `CancellationToken`.
- **`InternalSurfaceIsolationTests` green:** `HybridKeyCombiner` is internal and stays internal.

### Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | Key-combiner construction in `docs/format.md` before implementation, with security rationale | ✔ §3.5.1 and §3.5.2, written before any code; construction confirmed with the maintainer first |
| 2 | Both "one credential wrong" tests pass, proving both inputs contribute | ✔ and strengthened — see *The two tests the plan singled out* |
| 3 | Round-trips across all cipher and parameter-set combinations | ✔ 4 ciphers × 3 parameter sets, plus RSA-3072 across all three sets |
| 4 | Header authenticated as AAD, key-confirmation tag present, consistent with the other four | ✔ same `HeaderWriter`/`HeaderReader`/`PayloadCipher` path; AAD identity swept by `HeaderRoundTripTests` |
| 5 | Inspector, DI registration, file-path extensions and `docs/guides/` all extended | ✔ plus the fixture inventory, the malformed sweep and the thread-safety suite |
| 6 | `RELEASENOTES.md` records it; README *Features* list updated | ✔ and `PackageReleaseNotes` + `Description` kept in step |
| 7 | `BouncyCastleIsolationTests` still passes | ✔ |
| 8 | Zero-warning Release build; full suite green on both test TFMs | ✔ |
