# CLAUDE.md

Guidance for Claude Code (and other AI agents) working in this repository.

## Current state

**This repository is a bootstrap skeleton.** `FEATURE-67FD` stood up the git repo, the root
configuration, an empty multi-targeted library and an MTP-native xUnit v3 test project with a single
smoke test. There is **no production code yet** — `src/Enigma.DataEncryption/` contains only an
`AssemblyInfo.cs`.

Everything under *Planned architecture* below is the agreed design recorded in `docs/plan/`, not code
that exists. Read the plan file before implementing any of it; the plan is the contract.

## What this is (planned)

**Enigma.DataEncryption** is a .NET library that encrypts arbitrary data and streams into a
**self-describing binary container** — a header carrying everything a reader needs to decrypt,
followed by an AEAD payload. It is built on [Enigma.Core](https://www.nuget.org/packages/Enigma.Core),
which supplies every cryptographic primitive.

It is the successor to `Enigma.Cryptography.DataEncryption`.

## Planned architecture

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

The normative binary format will live in `docs/format.md` (`FEATURE-00E7`). **It is the contract** —
code and spec must agree on every offset, size and constant.

**Load-bearing invariant — BouncyCastle never leaks onto the public surface.** BouncyCastle backs
Enigma.Core, which backs this library, but no `Org.BouncyCastle.*` type may appear on any exported
type or member. `FEATURE-00E7` adds a reflection guard test
(`tests/Enigma.DataEncryption.UnitTests/Api/BouncyCastleIsolationTests.cs`, modelled on Enigma.Core's)
that walks every exported type and fails the build on a violation. Keep it green.

**Async / progress / cancellation.** Every operation is `async`, taking an optional
`IProgress<int>` (payload bytes processed — header bytes are not counted) and a `CancellationToken`.

## Project layout

```
Enigma.DataEncryption.slnx           Solution (SLNX format)
Directory.Build.props                Shared build defaults (Authors, Copyright, LangVersion 14, Nullable, TreatWarningsAsErrors)
Directory.Packages.props             Central Package Management (all package versions pinned here)
.editorconfig                        Code style + analyzer severities
global.json                          SDK 10.0.100 (latestFeature); test runner = Microsoft.Testing.Platform
README.md, RELEASENOTES.md           Empty — written at release time (FEATURE-07DA)
src/Enigma.DataEncryption/           The library
  Properties/AssemblyInfo.cs         InternalsVisibleTo for the test assembly
tests/Enigma.DataEncryption.UnitTests/   xUnit v3 test suite
  SmokeTest.cs                       Toolchain smoke test
docs/roadmap.md                      Work-item registry
docs/plan/                           Per-item plans
docs/done/                           Per-dev completion records
```

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
  missing comment fails the build. Per-category usage guides will live under `docs/guides/`
  (`FEATURE-07DA`).
- **Packaging metadata** (`PackageId`, `Version`, `Description`, …) is deliberately absent from the
  library csproj until release time (`FEATURE-07DA`), per the `dotnet-release` skill.

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

The planned sequence is a hard dependency chain: `FEATURE-67FD` → `FEATURE-00E7` (format spec + API
skeleton) → `FEATURE-11B6` (implementation, 5 phases) → `FEATURE-07DA` (v1.0.0 release, 4 phases).
`FEATURE-136E` (legacy decrypt) and `FEATURE-5A30` (hybrid method) are deferred by design and are not
part of v1.0.0.
