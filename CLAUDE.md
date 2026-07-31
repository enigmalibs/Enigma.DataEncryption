# CLAUDE.md

Guidance for Claude Code (and other AI agents) working in this repository.

## Current state

**The five implemented methods are functionally complete. One planned item now stands between the
library and the release** — `FEATURE-F612` (a full adversarial audit, whose findings become a
`CODE-REVIEW` item). See *Dev workflow* below; `docs/roadmap.md` is authoritative. `FEATURE-67FD` stood up the git
repo, the root configuration, the multi-targeted library and an MTP-native xUnit v3 test project.
`FEATURE-00E7` then added the normative format spec (`docs/format.md`) and the **complete public API
surface** — enums, constants, limits, the header record, the exception hierarchy, five service interfaces
with their implementations, the file-path extensions, the DI registration and the internal `IRandomSource`
seam — all fully XML-documented.

`FEATURE-11B6` filled in the behaviour across five phases **without changing a single signature**, and is
**done**. If you find yourself needing to change one now, stop and reconcile the spec first.

- **`PHASE01`** — the internal format machinery under `Internal/`: the header writer and reader (the reader
  tees the bytes it consumes, so the GCM associated data is definitionally what was on the wire), key
  confirmation, limit validation, cipher resolution, and the constant-time/clearing helpers.
- **`PHASE02`** — the two password-based services, pinned by golden vectors computed outside this library
  (Python's `hashlib`/`hmac`, OpenSSL's `ARGON2ID`, the platform's `AesGcm`), with the payload stage and the
  credential handling factored into `Internal/PayloadCipher.cs` and `Internal/PasswordCredential.cs`.
- **`PHASE03`** — the RSA service, transporting its data key under RSAES-OAEP (fixed at SHA-256 then;
  `FEATURE-0D64` later made the hash a header field), with golden vectors
  that pin every byte OAEP's own randomness allows (the wrapped key is the exception, and the suite says so)
  and committed PEM fixtures for the read path.
- **`PHASE04`** — the ML-KEM service, taking the encapsulated shared secret directly as its data key (the one
  method that draws no key material of its own). Here the key-confirmation tag earns its keep: FIPS 203
  implicit rejection makes decapsulation with a wrong key *succeed*, and the suite proves that against
  Enigma.Core first, then proves the tag rejects it before a payload byte is read.
- **`PHASE05`** — the inspector, the twelve file-path extensions, and the cross-cutting suites that needed
  all four methods present: a generated malformed-input sweep (asserting the exception is always one of the
  two container types and never an indexing, allocation or unwrapped Enigma.Core failure — now ~4,700 cases
  per TFM, after `FEATURE-5A30` added a fifth shape and `FEATURE-0D64` a fifth edited selector),
  thread-safety for all five singletons, DI round-trips through resolved services, and
  an executable inventory of every committed fixture.

`FEATURE-5A30` then added the **fifth method, the hybrid `0x05`** — the only one taking two credentials —
claiming the reserved method byte with no format-version bump. Its one genuinely new construction is the
**key combiner** (`docs/format.md` §3.5.1); see the load-bearing note below before touching it. It also
widened everything the phase list above describes as covering four methods: there are now **fourteen**
file-path extensions, the malformed-input sweep runs over five shapes (the hybrid's 1,066-byte header
included, truncated at every offset), and the thread-safety suite drives six singletons.

`FEATURE-0D64` then made method `0x03`'s **RSA-OAEP padding hash a header field** — SHA-256 (default),
SHA-384 or SHA-512, selected at encrypt time and read from the container at decrypt time; SHA-1 rejected and
its wire byte reserved. It claimed **offset 5**, where ML-KEM and the hybrid already put their parameter set,
so the `0x03` header grew from `37 + N` to `38 + N` and **every offset past 4 moved**. Two consequences are
easy to trip over: the two public-key shapes are now structurally identical at `38 + N` (`FormatLayoutTests`
asserts their equality, where it once asserted a one-byte difference), and the hybrid `0x05` deliberately did
**not** follow — its wrap stays fixed at OAEP-SHA-256, so `docs/format.md` §4's wrapping row is normative for
`0x05` alone. Format version stayed `0x10`.

**Nothing in the library throws `NotImplementedException` any more.** All six services, the file-path
extensions, `AddEnigmaDataEncryption()` and `RandomSource` are real. The suite is ~28,272 tests over both
test TFMs, with the library at ~98% line / ~92% branch coverage.

Two behaviours worth knowing before you touch the file-path extensions: **arguments are validated before
either file is opened** (the output is `FileMode.Create`, so validating later would truncate a caller's
existing file only to delete it again), and **the output handle is closed before the cleanup delete runs**
(deleting a file the process still holds open fails on Windows). Both are asserted; neither is incidental.

One thing PHASE03 settled that matters beyond it: **Enigma.Core reports a wrong RSA private key and an
undecryptable private-key PEM identically**, so `docs/format.md` §9 now wraps both as
`DataDecryptionException` (cause preserved as `InnerException`) and reserves the propagate-unwrapped rule
for PEMs that cannot be *parsed* (`ArgumentException` / `FormatException`). Do not try to re-split them by
message text.

**PHASE04 hit the same wall and applied the same rule, so §9 is now asymmetric between the two ML-KEM
directions on purpose.** `Decapsulate` raises one `CryptographicException` for a malformed private key, a key
for another parameter set, *and* a container whose parameter-set byte was edited — the caller's fault and the
file's fault, indistinguishable without message text. All three therefore wrap as `DataDecryptionException`,
because announcing an argument error for a tampered file is the worse mistake (and PHASE05's malformed-input
sweep admits only the two container exception types). `Encapsulate` has no such ambiguity — it takes the
public key and nothing else — so it becomes `ArgumentException` on `publicKey`. Do not "fix" the asymmetry.

`docs/format.md` is the contract for all of it. Read it and the relevant `docs/plan/<ID>.md` before
implementing.

## What this is

**Enigma.DataEncryption** is a .NET library that encrypts arbitrary data and streams into a
**self-describing binary container** — a header carrying everything a reader needs to decrypt,
followed by an AEAD payload. It is built on [Enigma.Core](https://www.nuget.org/packages/Enigma.Core),
which supplies every cryptographic primitive.

It is the successor to `Enigma.Cryptography.DataEncryption`.

## Architecture

Five encryption **methods**, one service each, plus an inspector:

| Method | Byte | Service | Credential |
|---|---|---|---|
| PBKDF2 | `0x01` | `IPbkdf2DataEncryptionService` | password |
| Argon2 | `0x02` | `IArgon2DataEncryptionService` | password |
| RSA | `0x03` | `IRsaDataEncryptionService` | RSA key pair (PEM) — the only method with a selectable OAEP hash |
| ML-KEM | `0x04` | `IMLKemDataEncryptionService` | ML-KEM key pair (raw bytes) |
| Hybrid | `0x05` | `IHybridDataEncryptionService` | **both** — an RSA key pair (PEM) *and* an ML-KEM key pair (raw bytes) |

`IEncryptedDataInspector` reads a container's header without decrypting it. Method bytes `0x06`–`0xFF` are
unassigned and rejected; `0x05` was reserved and is now assigned, which is the reservation from
`FEATURE-00E7` working as intended — the hybrid landed with no format-version bump.

**Method `0x03`'s wrapping hash is a header field (offset 5); the hybrid's is not.** `FEATURE-0D64` made
`0x03` selectable — SHA-256 (default), SHA-384 or SHA-512, with SHA-1 rejected and its wire byte `0x01`
reserved — and deliberately left `0x05` on a fixed OAEP-SHA-256 wrap, because the hybrid's wrap is one input
to the key combiner rather than the whole of key transport and carries no compliance argument of its own. So
`docs/format.md` §4's wrapping row is normative for **`0x05` alone**, and `0x03` points at §3.3. Do not
"restore the symmetry" by giving the hybrid a hash field: that would need a format change for no benefit, and
§3.5.1's transcript would have to cover the new byte.

Two things this makes true and easy to forget. **The two public-key shapes are now the same length** —
`0x03` and `0x04` are both `38 + N`, each with a one-byte algorithm selector at offset 5 — and
`RsaOaepHashWire`/`MLKemParameterSetWire` keep **separate** wire mappings and separate `FormatLayout`
constants for that shared offset on purpose, so each shape's arithmetic still reads on its own. **Decryption
takes no hash argument** anywhere: the reader resolves offset 5, so an edited byte fails as an OAEP unwrap
error rather than needing a rule of its own.

Every method derives, transports or combines a 32-byte data key, then encrypts the payload with a
**256-bit AEAD block cipher in GCM mode** (AES / Twofish / Serpent / Camellia), passing the
**complete header as AAD** so any header edit is an authentication failure. A **key-confirmation tag**
in the header gives uniform, fast, wrong-credential detection before a single payload byte is read,
and makes the construction key-committing (plain GCM is not).

The normative binary format is `docs/format.md`. **It is the contract** — code and spec must agree on
every offset, size and constant. `tests/…/Api/FormatConstantsTests.cs` enforces that agreement for the
constants and the five header lengths; keep both sides in step when either changes.

**Load-bearing invariant — BouncyCastle never leaks onto the public surface.** BouncyCastle backs
Enigma.Core, which backs this library, but no `Org.BouncyCastle.*` type may appear on any exported
type or member. The reflection guard
(`tests/Enigma.DataEncryption.UnitTests/Api/BouncyCastleIsolationTests.cs`, modelled on Enigma.Core's)
walks every exported type and fails the build on a violation. Keep it green.

**Watch the ML-KEM parameter-set byte.** Enigma.Core's `MLKemParameterSet` is an unnumbered enum
(`0`/`1`/`2`), but the header bytes are `0x01`/`0x02`/`0x03`. Map explicitly — never cast. Methods `0x04` and
`0x05` share both the field and its offset 5.

**Load-bearing invariant — the hybrid key combiner is a *split-key PRF*, not an XOR of the two secrets.**
`docs/format.md` §3.5.1 specifies it, §3.5.2 states the rationale, and `Internal/HybridKeyCombiner.cs`
implements it. Two things about it are easy to "simplify" and must not be:

- **Each secret keys its own HMAC** and never appears in a message. That is what makes "secure if *either*
  secret is secure" a one-line reduction from "HMAC is a PRF" — the same assumption key confirmation already
  makes. Concatenating the secrets into one HMAC message (the HKDF-Extract shape the plan sketched) was
  considered and rejected: it needs HMAC's *dual*-PRF property instead. XOR-ing the two secrets together
  gives neither property.
- **The two domain-separation labels differ.** With one shared label, `rsaSecret == kemSecret` makes the two
  branches identical and their XOR 32 zero bytes — a container readable by anyone holding neither private
  key. That is not a 2⁻²⁵⁶ accident: a hostile *sender* encapsulates first, sees `kemSecret`, then chooses
  what to wrap under RSA. `HybridKeyCombinerTests` pins both points, with a literal cross-language vector.

**Async / progress / cancellation.** Every operation is `async`, taking an optional
`IProgress<int>` (payload bytes processed — header bytes are not counted) and a `CancellationToken`.

## Project layout

```
Enigma.DataEncryption.slnx           Solution (SLNX format)
Directory.Build.props                Shared build defaults (Authors, Copyright, LangVersion 14, Nullable, TreatWarningsAsErrors)
Directory.Packages.props             Central Package Management (all package versions pinned here)
.editorconfig                        Code style + analyzer severities
global.json                          SDK 10.0.100 (latestFeature); test runner = Microsoft.Testing.Platform
README.md                            Packed nuget.org landing page (FEATURE-07DA PHASE03) — prose-only docs pointers
RELEASENOTES.md                      First-release notes; the single release-notes source (no CHANGELOG.md)
SECURITY.md                          Security policy — GitHub private vulnerability reporting, no email address
LICENSE.md                           MIT; named by PackageLicenseFile and packed
src/Enigma.DataEncryption/           The library
  Cipher.cs                          enum Cipher : byte            (0x01–0x04)
  EncryptionMethod.cs                enum EncryptionMethod : byte  (0x01–0x05; 0x06–0xFF unassigned)
  DataEncryptionDefaults.cs          Format version, fixed sizes, default KDF costs
  DataEncryptionLimits.cs            Header-field upper bounds (+ the shared Default)
  EncryptedDataHeader.cs             Parsed header record returned by the inspector
  DataEncryptionFileExtensions.cs    File-path wrappers (14 extension methods)
  ServiceCollectionExtensions.cs     AddEnigmaDataEncryption() — ns Microsoft.Extensions.DependencyInjection
  Exceptions/                        DataEncryptionException + Format/Decryption subclasses
  Services/                          The 5 encryption services + the inspector (interface + impl)
  Internal/                          The format machinery (all internal — see below)
    HeaderWriter.cs                  Builds, tags, writes and returns each of the 4 header shapes
    HeaderReader.cs                  Parses a header, tee-ing the AAD; translates Enigma.Core's stream failures
    ParsedHeader.cs                  Reader result: public header + raw AAD + method-specific key material
    CipherResolver.cs                Cipher ↔ header byte, and Cipher → IBlockCipherService
    KeyConfirmation.cs               kcKey / kcTag derivation + constant-time verification
    LimitsValidator.cs               Bounds every cost/length field before any allocation or KDF work
    PayloadCipher.cs                 The shared GCM payload stage (header as AAD) + the AEAD-failure translation
    PasswordCredential.cs            Password validation + the char[] → UTF-8 encoding both KDF methods share
    HybridKeyCombiner.cs             Method 0x05's split-key-PRF combiner (§3.5.1) — see the note above
    CryptoHelpers.cs                 FixedTimeEquals + Clear(params byte[]?[])
    FormatLayout.cs                  Magic bytes + the 5 header lengths (computed, not literal)
    MLKemParameterSetWire.cs         Explicit MLKemParameterSet ↔ wire-byte mapping (never cast)
    RsaOaepHashWire.cs               Explicit RsaOaepHash ↔ wire-byte mapping for method 0x03's offset 5
                                     (never cast; SHA-1 rejected both ways, its byte 0x01 reserved)
    IRandomSource.cs / RandomSource.cs   Internal RNG seam
  Properties/AssemblyInfo.cs         InternalsVisibleTo for the test assembly
tests/Enigma.DataEncryption.UnitTests/   xUnit v3 test suite
  SmokeTest.cs                       Toolchain smoke test
  Api/BouncyCastleIsolationTests.cs  Public-surface guard (the load-bearing invariant)
  Api/InternalSurfaceIsolationTests.cs  Guard: no Internal/ type is exported
  Api/FormatConstantsTests.cs        Pins the wire constants against docs/format.md
  DependencyInjection/               AddEnigmaDataEncryption() registration tests
  Internal/                          Format-infrastructure suites (round-trip, golden bytes,
                                     truncation sweep, validation, limits, key confirmation,
                                     hybrid key combiner)
  Services/                          Password-method suites (round-trip, failure/tamper, argument
                                     matrix, cancellation, golden vectors, key clearing) +
                                     Fixtures/ — committed containers & expected plaintext
docs/format.md                       Normative binary-format specification (the contract)
docs/guides/                         Per-category usage guides + index (README.md) — repo-only, not packed
                                     (7: password-based, rsa, ml-kem, hybrid, header-inspection,
                                      file-operations, dependency-injection)
docs/RELEASE.md                      Release runbook (FEATURE-07DA PHASE04) — pre-flight, merge, tag, pack, push
docs/roadmap.md                      Work-item registry
docs/plan/                           Per-item plans
docs/done/                           Per-dev completion records
docs/review/                         Audit findings reports — does not exist yet; created by FEATURE-F612 (repo-only, not packed)
```

Note the folders under `src/` are **organisational only** — every public type lives in the flat
`Enigma.DataEncryption` namespace (the DI extension excepted), so callers need one `using`. Internal
helpers are in `Enigma.DataEncryption.Internal`.

There is **no CI workflow**, deliberately — consistent with Enigma.Core and the predecessor. There is
no UI or CLI project, now or ever.

## Target frameworks & dependencies

- Library multi-targets **`netstandard2.0;net8.0;net10.0`** — mirroring Enigma.Core, so no consumer of
  Enigma.Core is excluded.
- Test project targets **`net8.0;net10.0`**. `netstandard2.0` is never a test TFM; its polyfill surface
  is exercised through the `net8.0` paths.
- Runtime dependencies: **Enigma.Core 1.0.0** and
  **Microsoft.Extensions.DependencyInjection.Abstractions 9.0.18** (all TFMs).
- `System.Buffers` and **PolySharp** (compile-only, `PrivateAssets=all`) are referenced on
  **netstandard2.0 only** — referencing `System.Buffers` on net8.0+ raises NU1510 and fails the
  zero-warnings build. PolySharp is what makes `init`/`required` members and the nullable-analysis
  attributes available on netstandard2.0.
- **Test-only:** `xunit.v3`, `coverlet.collector`, and **Microsoft.Extensions.DependencyInjection
  9.0.18** — the concrete container, needed to build a real `ServiceProvider` in the DI tests. The
  library depends on the *Abstractions* alone; this reference must never migrate into it.
- All versions are managed centrally in `Directory.Packages.props` — never put `Version=` on a
  `<PackageReference>`.

## Build & test

Zero-warning builds are enforced (`TreatWarningsAsErrors=true`, `EnforceCodeStyleInBuild=true`), so
warnings fail the build.

```bash
# Build the whole solution (Release)
dotnet build Enigma.DataEncryption.slnx -c Release

# Run the full test suite (Microsoft.Testing.Platform runner, per global.json)
dotnet test --solution Enigma.DataEncryption.slnx -c Release
```

Note the `--solution` flag: on the .NET 10 SDK in MTP mode, `dotnet test <Solution>.slnx` is rejected.

Tests are **MTP-native**: `xunit.v3` + `coverlet.collector`, with **no** `Microsoft.NET.Test.Sdk` and
**no** `xunit.runner.visualstudio` — both break the Microsoft Testing Platform.

## Conventions

- **Language/style.** C# 14, `Nullable=enable`, `ImplicitUsings=disable` (declare `using`s
  explicitly). Follow `.editorconfig`; do not introduce warnings.
- **Public surface.** Never expose a BouncyCastle type publicly. Reuse Enigma.Core's public types
  (e.g. `MLKemParameterSet`) rather than defining duplicates.
- **Documentation.** Public APIs carry XML doc comments (`GenerateDocumentationFile=true`), so a
  missing comment fails the build. Per-category usage guides live under `docs/guides/`, indexed by
  `docs/guides/README.md` (`FEATURE-07DA` PHASE02, extended by `FEATURE-5A30`) — seven guides, one per
  category, plus the index. They
  are **usage**; `docs/format.md` remains the spec, and no wire-format table is duplicated into them.
  Every snippet is verified against the real public surface of *both* this library and Enigma.Core;
  there is no permanent doc-sample test project, so that gate is a per-dev obligation, not a build step.
  Two constraints the guides depend on: they are **repo-only and never packed**, so their relative links
  (including `../format.md`) are correct as written and must not become absolute URLs — and the packed
  root `README.md` must therefore point at them in prose, with no clickable `docs/…` link.
- **Packaging metadata.** All 12 NuGet properties are now present in the library csproj
  (`FEATURE-07DA` PHASE01), together with the `None` `ItemGroup` that packs `README.md` and
  `LICENSE.md`. Two omissions there are deliberate, not oversights: **`GeneratePackageOnBuild` is
  off** (the package is packed explicitly by the release step, never on every local build) and **no
  symbol properties** are set, so a release ships exactly one file, the `.nupkg`. `PackageReleaseNotes`
  now mirrors the top of `RELEASENOTES.md` (PHASE03) and ends `See RELEASENOTES.md for the full details.`
  — the two are duplicated prose kept in step only by a csproj comment, so change them together.

## Dev workflow (tracked work)

This repo plans and tracks work through a house workflow:

- `docs/roadmap.md` — the single registry of every work item (`FEATURE-HHHH`, `BUG-HHHH`,
  `CODE-REVIEW-HHHH`; large items are split into `-PHASENN` phases).
- `docs/plan/<ID>.md` — the full plan for each item (the contract a build implements).
- `docs/done/<ID>.md` — a completion record per finished item/phase.

Each unit of work gets its own branch (`feature/…`, `bugfix/…`, `review/…`), cut from the current
`HEAD`. A unit is **done** only when the build is warning-free, the whole test suite passes, the
plan's acceptance criteria are met, the roadmap/plan statuses are updated, and the completion doc is
written. Commits are left to the maintainer.

The sequence is a hard dependency chain: `FEATURE-67FD` (done) → `FEATURE-00E7` (done — format spec +
API skeleton) → `FEATURE-11B6` (done — all five phases) → `FEATURE-07DA` (done — all four phases; the
package, the docs and the runbook are prepared) → `FEATURE-5A30` (done — hybrid method `0x05`) →
`FEATURE-0D64` (done — selectable RSA-OAEP hash) → **`FEATURE-F612`** (adversarial audit, report only) →
the **`CODE-REVIEW`** item minted from that report → the maintainer runs `docs/RELEASE.md`.

**v1.0.0 is prepared but *not published*, and the release now waits on `FEATURE-F612` and the
`CODE-REVIEW` item its report mints** — do not treat the library as one step from shipping.

**Both format items have now spent the pre-publication window, and it is the last one.** That no container
exists outside this repository is what let `FEATURE-5A30` add a header shape and three fixtures, and
`FEATURE-0D64` move every `0x03` offset past 4, each for nothing but the cost of generating fixtures — both
with format version staying `0x10`. Publishing closes that window: a further header change would cost a
version bump or a second method byte. `FEATURE-F612` is deliberately **last**, so it audits the code that
actually ships, and it is under a hard code freeze — it writes findings to `docs/review/`, fixes nothing.

`FEATURE-136E` (legacy decrypt) is **`ABANDONED`** — the predecessor-file migration need never
materialized — though format versions `0x01`–`0x0F` stay reserved, so it could return as a new item
without a redesign. Bringing back the predecessor's PKCS#1 v1.5 key wrapping is **not** planned either;
`FEATURE-0D64` records why. `docs/roadmap.md` is authoritative for current status.
