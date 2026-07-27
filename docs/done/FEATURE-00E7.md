# FEATURE-00E7 — Binary format spec & public abstraction skeleton (DONE)

## Summary

Wrote the normative binary-format specification (`docs/format.md`) and the complete public API surface
of the library — two enums, two constant/limit types, a header record, a three-type exception
hierarchy, five service interfaces with their implementations, the file-path extension class, the DI
registration, and the internal `IRandomSource` seam. Every public type and member carries an XML doc
comment; every behavioural implementation body throws `NotImplementedException`, as the plan scopes.

Two things are genuinely implemented rather than stubbed, because the plan's own acceptance criteria
require them to work: **`AddEnigmaDataEncryption()`** (criterion 6 asks it to resolve all five
services from a real `ServiceCollection`) and **`RandomSource`** (a one-line delegation to
Enigma.Core's `RandomUtils`).

The BouncyCastle-isolation guard test is in place from this point forward, mirroring Enigma.Core's
traversal member-for-member, so the load-bearing invariant is protected before any code exists that
could violate it.

The shape of the library is now settled: FEATURE-11B6 fills in behaviour without changing a signature.

## Files/modules touched

### Created — specification
- `docs/format.md` — the normative contract, 10 sections: integer encoding and offset conventions;
  the common 5-byte prefix; all four method bodies with exact offsets and sizes; the fixed-parameter
  table and why none of it is header-selectable; the AAD rule and why it is not circular with key
  confirmation; the key-confirmation derivation with its three documented consequences; the canonical
  encrypt/decrypt operation orders; the limits table and the before-any-allocation rule; the complete
  error mapping; and the reserved-value summary.

### Created — public API (`src/Enigma.DataEncryption/`)
- `Cipher.cs` — `public enum Cipher : byte` (`0x01`–`0x04`)
- `EncryptionMethod.cs` — `public enum EncryptionMethod : byte` (`0x01`–`0x04`; `0x05` reserved and
  deliberately **not** a member)
- `DataEncryptionDefaults.cs` — format version, the four default cost parameters, and the five fixed
  sizes
- `DataEncryptionLimits.cs` — six `init` bounds plus the shared `Default` instance
- `EncryptedDataHeader.cs` — `sealed record` with four `required` members and seven method-specific
  nullables
- `DataEncryptionFileExtensions.cs` — 12 extension methods (see *Deviations*), each documenting the
  three file semantics
- `Exceptions/DataEncryptionException.cs`, `Exceptions/DataEncryptionFormatException.cs`,
  `Exceptions/DataDecryptionException.cs`
- `Services/IPbkdf2DataEncryptionService.cs` + `Services/Pbkdf2DataEncryptionService.cs`
- `Services/IArgon2DataEncryptionService.cs` + `Services/Argon2DataEncryptionService.cs`
- `Services/IRsaDataEncryptionService.cs` + `Services/RsaDataEncryptionService.cs`
- `Services/IMLKemDataEncryptionService.cs` + `Services/MLKemDataEncryptionService.cs`
- `Services/IEncryptedDataInspector.cs` + `Services/EncryptedDataInspector.cs`
- `Internal/IRandomSource.cs`, `Internal/RandomSource.cs` — the internal RNG seam
- `ServiceCollectionExtensions.cs` — `AddEnigmaDataEncryption()`, in namespace
  `Microsoft.Extensions.DependencyInjection`

### Created — tests (`tests/Enigma.DataEncryption.UnitTests/`)
- `Api/BouncyCastleIsolationTests.cs` — the public-surface guard, plus a second fact asserting
  `GetExportedTypes()` is non-empty so the sweep can never pass vacuously
- `Api/FormatConstantsTests.cs` — pins every wire constant and the four header lengths against
  `docs/format.md`
- `DependencyInjection/ServiceCollectionExtensionsTests.cs` — resolution of all five services and all
  six Enigma.Core factories, singleton identity, chaining, null-guard, `TryAdd*` survival, idempotence

### Modified
- `Directory.Packages.props` — added `Microsoft.Extensions.DependencyInjection` 9.0.18 (**test-only**)
- `tests/…/Enigma.DataEncryption.UnitTests.csproj` — references it
- `docs/roadmap.md`, `docs/plan/FEATURE-00E7.md` — status `TODO` → `IN PROGRESS` → `DONE`

## Deviations & follow-ups

- **File extensions: 12 methods, not 8 — confirmed with the maintainer mid-build.** The plan says
  "one pair per service" and shows only the `byte[]` password form, but the stream API gives PBKDF2
  and Argon2 both `byte[]` and `char[]` password overloads. Omitting `char[]` from the file helpers
  would force a `char[]`-holding caller to hand-encode and hand-clear a temporary buffer — exactly the
  care the `char[]` stream overloads exist to provide. Asked before writing the class, since this dev
  freezes the public surface; the maintainer chose the wider set.

- **`AddEnigmaDataEncryption()` builds the four encryption services through explicit factory lambdas
  rather than by type.** The plan asks for both `TryAddSingleton<IRandomSource, RandomSource>()` and
  the five services registered. Registering the services by type would have made the `IRandomSource`
  registration dead code: `Microsoft.Extensions.DependencyInjection` only considers **public**
  constructors, and `IRandomSource` is internal, so it cannot appear on one (CS0051). The public
  3-argument constructors therefore fall back to `new RandomSource()` internally. Using
  `sp => new XService(…, sp.GetRequiredService<IRandomSource>())` reaches the internal constructor and
  makes the seam genuinely substitutable through the container — which is the only reading under which
  the plan's `IRandomSource` registration does anything. `IEncryptedDataInspector` has no
  dependencies and is still registered by type.

- **Two constructors per encryption service.** A public parameterless one (`new RandomSource()` plus
  Enigma.Core's concrete factories) so the types are usable without DI, per the plan's "public
  parameterless (or factory-only) construction path"; a public factory-taking one, which is what a
  container resolves; and the internal one that also takes `IRandomSource`. No DI ambiguity — MS.DI
  picks the greediest resolvable constructor, and `{}` is a strict subset of `{factories}`.

- **Namespace is flat (`Enigma.DataEncryption`) even though files sit in `Exceptions/`, `Services/`
  and `Internal/` folders**, exactly as the plan's Layout section specifies. This diverges from
  Enigma.Core, which matches namespaces to folders. `.editorconfig` sets
  `dotnet_style_namespace_match_folder = true:suggestion` — *suggestion*, so it does not fail the
  zero-warning build. Flagging it because it is a visible inconsistency between the two sibling
  repositories, not a defect: the plan chose the flat namespace deliberately so callers need one
  `using`.

- **`Microsoft.Extensions.DependencyInjection` 9.0.18 added as a test-only package.** The library
  depends on the Abstractions alone; building a real `ServiceProvider` for acceptance criterion 6
  needs the concrete container. Version-matched to the Abstractions pin. A comment in both
  `Directory.Packages.props` and the test csproj records that it must never migrate into the library.

- **`FormatConstantsTests` is an addition beyond the plan's test list.** Acceptance criterion 9 —
  "`docs/format.md` and the code agree on every constant… cross-check the offset arithmetic field by
  field" — is stated as a manual review step. A manual check protects the constants once; this test
  protects them for every future build, and it is what caught nothing this time only because the
  constants were transcribed carefully. It asserts literals transcribed from the spec, never a
  constant against itself.

- **Two errors found and fixed in `docs/format.md` during the final cross-check**, both in §1.1: the
  worked big-endian-misparse example gave `−1070373632` where the correct value is `−1071183616`
  (verified with `struct.unpack`), and the cited Enigma.Core type was named `StreamExtensions` where
  the actual type is `StreamExtensionsInt32`. The key-confirmation label's stated length (27 bytes)
  and hex encoding were verified byte-for-byte and were correct.

- **ML-KEM parameter-set byte is a wire encoding, not the enum value — now called out explicitly in
  the spec (§3.4).** `Enigma.Core.Asymmetric.Pqc.MLKemParameterSet` is an unnumbered C# enum, so its
  members are `0`/`1`/`2`, while the header bytes are `0x01`/`0x02`/`0x03`. An implementer who casts
  instead of mapping would write ML-KEM-512 containers as `0x00`. The plan implied the mapping; the
  spec now states it and says "must not cast". This is the highest-risk detail handed to
  FEATURE-11B6 PHASE04.

- **Line endings (CRLF):** none observed. A scan of every `.cs`/`.csproj`/`.props`/`.md`/`.json`/
  `.slnx` outside `bin`/`obj` found zero CR bytes. No action taken (recommendation-only per
  `dev-workflow`).

- **No commit performed**, per the "never commit yourself" rule. Branch
  `feature/feature-00e7-abstractions` was cut from `develop` at `554d5fd`.

## Build/test evidence

- **Build:** `dotnet build Enigma.DataEncryption.slnx -c Release --no-incremental` →
  `Build succeeded. 0 Warning(s) 0 Error(s)` across all three library TFMs (`netstandard2.0`,
  `net8.0`, `net10.0`) and both test TFMs, with `TreatWarningsAsErrors=true` and
  `EnforceCodeStyleInBuild=true` in force.
- **Test:** `dotnet test --solution Enigma.DataEncryption.slnx -c Release` →
  `total: 78, failed: 0, succeeded: 78, skipped: 0` — green on both `net8.0` and `net10.0`.
- **XML-doc enforcement verified empirically**, not assumed: a temporary undocumented public type was
  added and the build failed with `error CS1591` on all three TFMs; the probe file was then removed.
  No `NoWarn`, `#pragma warning` or `SuppressMessage` exists anywhere in `src/`.
- **Exported surface enumerated** from the generated `Enigma.DataEncryption.xml` (113 documented
  members) and checked against the plan's Layout section: all 20 public types present, no extras.
- **No duplicate `MLKemParameterSet`** — `grep -rn "enum MLKemParameterSet" src/` returns nothing; the
  public surface uses `Enigma.Core.Asymmetric.Pqc.MLKemParameterSet`, confirmed in the generated XML
  signatures.
- **Spec/code cross-check** is executable, in `FormatConstantsTests`: method bytes, cipher bytes,
  format version, the five fixed sizes, `GcmMacSizeBits == GcmMacSize.MaxBits`, the four default cost
  parameters, all six default limits, and the four header lengths recomputed from the size constants
  (53 / 61 / 37 + N / 38 + N). All pass.
- **`0x05` is not a defined `EncryptionMethod` member** — asserted, not merely omitted.

## Acceptance criteria — all met

1. ✅ `docs/format.md` exists and covers every required element: common prefix (§2); all four method
   bodies with exact offsets and sizes (§3); little-endian `Int32` stated explicitly with a worked
   misparse example (§1.1); the fixed-parameter table (§4); the AAD rule and its non-circularity with
   key confirmation (§5); the key-confirmation derivation with both documented consequences — key
   commitment and the header-only guessing note (§6.3); the limits table (§8); the canonical
   encrypt/decrypt operation orders (§7); the reserved `0x05` method and `0x01`–`0x0F` version range
   (§2.2, §2.3, §10); and the `memorySizeKb` divergence from the predecessor, including the field-order
   difference (§3.2).
2. ✅ Every type in the Layout section exists with the specified signatures — verified against the
   generated XML surface dump.
3. ✅ `MLKemParameterSet` is Enigma.Core's type; no duplicate enum in this library.
4. ✅ Every public type and member carries an XML doc comment — enforced by the build (CS1591 as an
   error, empirically confirmed). The per-method notes are present on every method: progress reports
   payload bytes only, neither stream is disposed, decryption needs no seekable stream, internally
   derived key material is cleared while caller-supplied credentials are not, and `limits: null` means
   `DataEncryptionLimits.Default`.
5. ✅ `dotnet build -c Release` succeeds with zero warnings on all three library TFMs, with
   `GenerateDocumentationFile` on.
6. ✅ `AddEnigmaDataEncryption()` resolves all five services (and all six Enigma.Core factories) from a
   real `ServiceCollection`; every registration uses `TryAdd*`, asserted by both the pre-registered
   factory surviving and the method being idempotent.
7. ✅ `BouncyCastleIsolationTests` passes, with the same traversal as Enigma.Core's — base types,
   interfaces, generic arguments, methods (return + parameters, including property/event accessors),
   constructors and fields, unwrapping arrays/by-ref/pointers — plus a non-vacuity guard Enigma.Core's
   does not have.
8. ✅ Full suite green: smoke test, guard tests, format-constant tests and DI tests. No test asserts
   behaviour that is still `NotImplementedException`.
9. ✅ `docs/format.md` and the code agree on every constant, now enforced by `FormatConstantsTests`
   rather than by inspection alone. The offset arithmetic was cross-checked field by field; two
   documentation errors were found and corrected (see *Deviations*).
