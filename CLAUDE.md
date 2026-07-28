# CLAUDE.md

Guidance for Claude Code (and other AI agents) working in this repository.

## Current state

**The library is functionally complete; what remains is the release.** `FEATURE-67FD` stood up the git
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
- **`PHASE03`** — the RSA service, transporting its data key under RSAES-OAEP-SHA256, with golden vectors
  that pin every byte OAEP's own randomness allows (the wrapped key is the exception, and the suite says so)
  and committed PEM fixtures for the read path.
- **`PHASE04`** — the ML-KEM service, taking the encapsulated shared secret directly as its data key (the one
  method that draws no key material of its own). Here the key-confirmation tag earns its keep: FIPS 203
  implicit rejection makes decapsulation with a wrong key *succeed*, and the suite proves that against
  Enigma.Core first, then proves the tag rejects it before a payload byte is read.
- **`PHASE05`** — the inspector, the twelve file-path extensions, and the cross-cutting suites that needed
  all four methods present: a generated malformed-input sweep (~2,600 corrupted containers per TFM, asserting
  the exception is always one of the two container types and never an indexing, allocation or unwrapped
  Enigma.Core failure), thread-safety for all five singletons, DI round-trips through resolved services, and
  an executable inventory of every committed fixture.

**Nothing in the library throws `NotImplementedException` any more.** All five services, the file-path
extensions, `AddEnigmaDataEncryption()` and `RandomSource` are real. The suite is ~16,150 tests over both
test TFMs, with the library at ~97% line / ~91% branch coverage.

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

Four encryption **methods**, one service each, plus an inspector:

| Method | Byte | Service | Credential |
|---|---|---|---|
| PBKDF2 | `0x01` | `IPbkdf2DataEncryptionService` | password |
| Argon2 | `0x02` | `IArgon2DataEncryptionService` | password |
| RSA | `0x03` | `IRsaDataEncryptionService` | RSA key pair (PEM) |
| ML-KEM | `0x04` | `IMLKemDataEncryptionService` | ML-KEM key pair (raw bytes) |

`IEncryptedDataInspector` reads a container's header without decrypting it. `0x05` is **reserved**
for a true RSA + ML-KEM hybrid (`FEATURE-5A30`, deferred).

Every method derives or transports a 32-byte data key, then encrypts the payload with a
**256-bit AEAD block cipher in GCM mode** (AES / Twofish / Serpent / Camellia), passing the
**complete header as AAD** so any header edit is an authentication failure. A **key-confirmation tag**
in the header gives uniform, fast, wrong-credential detection before a single payload byte is read,
and makes the construction key-committing (plain GCM is not).

The normative binary format is `docs/format.md`. **It is the contract** — code and spec must agree on
every offset, size and constant. `tests/…/Api/FormatConstantsTests.cs` enforces that agreement for the
constants and the four header lengths; keep both sides in step when either changes.

**Load-bearing invariant — BouncyCastle never leaks onto the public surface.** BouncyCastle backs
Enigma.Core, which backs this library, but no `Org.BouncyCastle.*` type may appear on any exported
type or member. The reflection guard
(`tests/Enigma.DataEncryption.UnitTests/Api/BouncyCastleIsolationTests.cs`, modelled on Enigma.Core's)
walks every exported type and fails the build on a violation. Keep it green.

**Watch the ML-KEM parameter-set byte.** Enigma.Core's `MLKemParameterSet` is an unnumbered enum
(`0`/`1`/`2`), but the header bytes are `0x01`/`0x02`/`0x03`. Map explicitly — never cast.

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
  EncryptionMethod.cs                enum EncryptionMethod : byte  (0x01–0x04; 0x05 reserved)
  DataEncryptionDefaults.cs          Format version, fixed sizes, default KDF costs
  DataEncryptionLimits.cs            Header-field upper bounds (+ the shared Default)
  EncryptedDataHeader.cs             Parsed header record returned by the inspector
  DataEncryptionFileExtensions.cs    File-path wrappers (12 extension methods)
  ServiceCollectionExtensions.cs     AddEnigmaDataEncryption() — ns Microsoft.Extensions.DependencyInjection
  Exceptions/                        DataEncryptionException + Format/Decryption subclasses
  Services/                          The 4 encryption services + the inspector (interface + impl)
  Internal/                          The format machinery (all internal — see below)
    HeaderWriter.cs                  Builds, tags, writes and returns each of the 4 header shapes
    HeaderReader.cs                  Parses a header, tee-ing the AAD; translates Enigma.Core's stream failures
    ParsedHeader.cs                  Reader result: public header + raw AAD + method-specific key material
    CipherResolver.cs                Cipher ↔ header byte, and Cipher → IBlockCipherService
    KeyConfirmation.cs               kcKey / kcTag derivation + constant-time verification
    LimitsValidator.cs               Bounds every cost/length field before any allocation or KDF work
    PayloadCipher.cs                 The shared GCM payload stage (header as AAD) + the AEAD-failure translation
    PasswordCredential.cs            Password validation + the char[] → UTF-8 encoding both KDF methods share
    CryptoHelpers.cs                 FixedTimeEquals + Clear(params byte[]?[])
    FormatLayout.cs                  Magic bytes + the 4 header lengths (computed, not literal)
    MLKemParameterSetWire.cs         Explicit MLKemParameterSet ↔ wire-byte mapping (never cast)
    IRandomSource.cs / RandomSource.cs   Internal RNG seam
  Properties/AssemblyInfo.cs         InternalsVisibleTo for the test assembly
tests/Enigma.DataEncryption.UnitTests/   xUnit v3 test suite
  SmokeTest.cs                       Toolchain smoke test
  Api/BouncyCastleIsolationTests.cs  Public-surface guard (the load-bearing invariant)
  Api/InternalSurfaceIsolationTests.cs  Guard: no Internal/ type is exported
  Api/FormatConstantsTests.cs        Pins the wire constants against docs/format.md
  DependencyInjection/               AddEnigmaDataEncryption() registration tests
  Internal/                          Format-infrastructure suites (round-trip, golden bytes,
                                     truncation sweep, validation, limits, key confirmation)
  Services/                          Password-method suites (round-trip, failure/tamper, argument
                                     matrix, cancellation, golden vectors, key clearing) +
                                     Fixtures/ — committed containers & expected plaintext
docs/format.md                       Normative binary-format specification (the contract)
docs/guides/                         Per-category usage guides + index (README.md) — repo-only, not packed
docs/RELEASE.md                      Release runbook (FEATURE-07DA PHASE04) — pre-flight, merge, tag, pack, push
docs/roadmap.md                      Work-item registry
docs/plan/                           Per-item plans
docs/done/                           Per-dev completion records
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
  `docs/guides/README.md` (`FEATURE-07DA` PHASE02) — six guides, one per category, plus the index. They
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
API skeleton) → `FEATURE-11B6` (done — all five phases) → **`FEATURE-07DA` (done — all four phases;
v1.0.0 is prepared but *not published*, so the one step left is the maintainer running
`docs/RELEASE.md`)**. `FEATURE-136E` (legacy decrypt) and `FEATURE-5A30`
(hybrid method) are deferred by design and are not part of v1.0.0. `docs/roadmap.md` is authoritative
for current status.
