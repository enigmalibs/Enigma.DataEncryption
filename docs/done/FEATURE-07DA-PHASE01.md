# FEATURE-07DA-PHASE01 — Package metadata & build config + license audit

**Status:** DONE
**Branch:** `feature/feature-07da-phase01-metadata`

## Summary

Added the NuGet packaging metadata to the library csproj — all 12 properties the `dotnet-release`
skill requires, plus the `ItemGroup` that actually packs `README.md` and `LICENSE.md` — and audited
the licences of everything that ships. This is the first phase of the v1.0.0 release; it is the
only phase that touches the build configuration, and it is what makes `dotnet pack` produce a valid
artifact at all (PHASE04 verifies one).

Nothing about the library's behaviour changed: no source file was touched, no signature moved, and
the same 16,162 tests pass before and after. The csproj comment that said the packaging metadata was
"deliberately absent … added at release time" has been replaced by the metadata it was promising.

## Files touched

**Modified**

- `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj` — added the packaging `PropertyGroup`
  (12 properties) and the `None` packing `ItemGroup`; replaced the bootstrap "metadata deliberately
  absent" comment with one recording the two deliberate *omissions* (`GeneratePackageOnBuild`, symbol
  properties); added a one-line comment on `GenerateDocumentationFile` explaining what it buys.
- `docs/roadmap.md` — `FEATURE-07DA` and its `PHASE01` row → `IN PROGRESS`, then `PHASE01` → `DONE`.
- `docs/plan/FEATURE-07DA.md` — item status and PHASE01 status.
- `CLAUDE.md` — documentation-freshness sweep, two stale statements this phase invalidated: the
  *Conventions* bullet claiming the packaging metadata is "deliberately absent from the library csproj
  until release time" (now the opposite is true, so it instead records what is present and which two
  omissions are deliberate), and the *Dev workflow* sequence line calling `FEATURE-07DA` "next" (now
  in progress, PHASE01 done, PHASE02 next). The layout line saying `README.md` / `RELEASENOTES.md` are
  empty was **left alone** — it is still accurate until PHASE03 writes them.

**Created**

- `docs/done/FEATURE-07DA-PHASE01.md` (this file).

No source, test, or `Directory.*.props` file was modified. No package version was bumped (a
dependency refresh is not part of a first release's PHASE01).

## Package metadata — the 12 properties

Verified by evaluating them out of MSBuild rather than by reading the file
(`dotnet msbuild … -p:TargetFramework=net10.0 -getProperty:…`), so the values below are what the pack
target will actually see:

| # | Property | Value as evaluated |
|---|---|---|
| 1 | `PackageId` | `Enigma.DataEncryption` |
| 2 | `Version` | `1.0.0` |
| 3 | `Title` | `Enigma.DataEncryption — Stream Encryption for .NET` |
| 4 | `Description` | One paragraph: stream-based authenticated encryption on Enigma.Core; authenticated header + key-confirmation tag; PBKDF2 / Argon2id / RSA-OAEP-SHA256 / ML-KEM key establishment; AES-256, Twofish-256, Serpent-256, Camellia-256 in GCM; async with progress and cancellation; header inspection; one-call DI |
| 5 | `PackageTags` | `enigma encryption decryption cryptography stream aes gcm twofish serpent camellia rsa oaep ml-kem post-quantum pbkdf2 argon2 dotnet` |
| 6 | `PackageReadmeFile` | `README.md` |
| 7 | `PackageLicenseFile` | `LICENSE.md` |
| 8 | `RepositoryUrl` | `https://github.com/enigmalibs/Enigma.DataEncryption` |
| 9 | `RepositoryType` | `git` |
| 10 | `PackageProjectUrl` | `https://github.com/enigmalibs/Enigma.DataEncryption` |
| 11 | `PackageReleaseNotes` | First-release prose (four methods, authenticated header, key-confirmation tag, four GCM ciphers, async/progress/cancellation, inspection, file helpers, DI; TFMs; predecessor-incompatibility), ending `See RELEASENOTES.md for the full details.` |
| 12 | `GenerateDocumentationFile` | `true` — set at bootstrap by `FEATURE-67FD`, verified unchanged |

Property 11 is **provisional by plan**: `RELEASENOTES.md` is still a 0-byte placeholder, so this
prose was written to the plan's PHASE03 outline rather than mirrored from a real document. PHASE03
owns reconciling the two so the property genuinely mirrors the top of `RELEASENOTES.md`. It already
carries the mandated closing sentence, so the shape will not have to change — only the wording.

**Packing `ItemGroup`** — present, and confirmed by dumping the `None` items: both entries resolve to
`Pack=true`, `PackagePath=/`, `Link=README.md` / `LICENSE.md`, with `FullPath` at the repository root.
Naming the files in properties 6 and 7 does not pack them; this `ItemGroup` is what does.

**`GeneratePackageOnBuild`** — absent from every file in the repo (grep-verified across `*.csproj`,
`*.props`, `*.slnx`, `global.json`); it evaluates to `false` from the SDK default. The package is
packed explicitly by the release step, never on every local build.

## Symbols & SourceLink — deliberately not enabled

No symbol package. `IncludeSymbols`, `SymbolPackageFormat`, `PublishRepositoryUrl` and
`EmbedUntrackedSources` are absent from every file in the repo — the same grep as above matched only
the csproj comment naming them. `dotnet pack` will therefore emit the `.nupkg` and nothing else,
consistent with Enigma.Core.

One thing worth recording so a later reader does not misread it: evaluating those properties shows
`SymbolPackageFormat=symbols.nupkg` and `EmbedUntrackedSources=true`. **Those are .NET SDK defaults,
not opt-ins from this repo.** What actually gates symbol production is `IncludeSymbols`, which
evaluates to empty — so no `.snupkg` is produced. PHASE04's pack-verify asserts this against the real
output directory rather than trusting the reasoning here.

## Target-framework normalization — no change

`netstandard2.0;net8.0;net10.0`, confirmed by evaluation. This is **already** the normalized result:
the `netstandard` target is preserved and the plain-`net` targets are exactly the current LTS pair
(`net8.0` + `net10.0`). **No edit was made and none was needed**, so there is no `old → new`
transition to log, no *Compatibility* note for PHASE03 to write, and no compatibility surface moved.

## Third-party license audit

Audited **what ships** — runtime dependencies only. Every finding below was read out of the resolved
package in the local NuGet cache (`~/.nuget/packages/<id>/<version>/*.nuspec`), not from memory:

| Dependency | Version | Kind | Ships? | Licence, as declared | Redistribution |
|---|---|---|---|---|---|
| `Enigma.Core` | 1.0.0 | runtime, all TFMs | **yes** | `<license type="file">LICENSE.md</license>` — the packed `LICENSE.md` is the MIT grant + as-is disclaimer, © 2026 Josué Clément | **permitted** |
| `Microsoft.Extensions.DependencyInjection.Abstractions` | 9.0.18 | runtime, all TFMs | **yes** | `<license type="expression">MIT</license>` | **permitted** |
| `BouncyCastle.Cryptography` | 2.6.2 | runtime, **transitive** via Enigma.Core, all three TFMs | **yes** | `<license type="expression">MIT</license>` | **permitted** |
| `System.Buffers` | 4.6.1 | runtime, `netstandard2.0` only | **yes** | `<license type="expression">MIT</license>` | **permitted** |
| `PolySharp` | 1.16.0 | compile-only, `PrivateAssets=all` | no | MIT | not redistributed — out of scope |
| `xunit.v3` · `coverlet.collector` · `Microsoft.Testing.Extensions.CodeCoverage` · `Microsoft.Extensions.DependencyInjection` | 3.2.2 · 6.0.4 · 18.0.4 · 9.0.18 | test-only | no | — | never in the package — out of scope |

**Conclusion: every shipping dependency is MIT, and MIT permits redistribution.** This package is
itself MIT (`LICENSE.md` at the repository root), so there is no licence-compatibility conflict and
nothing to attribute beyond the notices already carried inside each dependency's own package.

Three details found while auditing that are worth keeping:

- **Enigma.Core's licence is a *file*, not an expression.** Its nuspec says
  `<license type="file">LICENSE.md</license>` with the deprecated-`licenseUrl` placeholder, so "MIT"
  had to be established by reading the packed text rather than by trusting a SPDX expression. It is
  MIT, word for word the same grant as this repository's own `LICENSE.md`.
- **`System.Buffers` and `PolySharp` both declare `requireLicenseAcceptance=true`.** That is a NuGet
  *client prompt* flag, not a redistribution restriction — the licence in both cases is MIT, which
  permits redistribution regardless. No action needed; recorded so the flag is not later mistaken for
  a blocker.
- **`System.Buffers 4.6.1` is not only ours.** Enigma.Core 1.0.0's own nuspec declares
  `System.Buffers 4.6.1` on `.NETStandard2.0`, so this library's explicit `netstandard2.0`-only
  reference matches its transitive floor exactly — no floor conflict for PHASE04 to reconcile.

`LICENSE.md` verification: present at the repository root (1,063 bytes, MIT), named by
`<PackageLicenseFile>`, and packed by the `None` item confirmed above.

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | All 12 properties present and correct; packing `ItemGroup` present; `GeneratePackageOnBuild` off | **met** — all 12 verified by MSBuild evaluation, not by eye; `None` items dumped and confirmed; `GeneratePackageOnBuild` grep-absent and evaluates `false` |
| 2 | TFM set confirmed already normalized, recorded | **met** — `netstandard2.0;net8.0;net10.0` unchanged; recorded above |
| 3 | License audit table completed, every shipping dependency verified | **met** — five shipping dependencies audited from their resolved nuspecs; all MIT |
| 4 | Zero-warning Release build; full suite still green | **met** — see below |

## Build / test evidence

```
dotnet build Enigma.DataEncryption.slnx -c Release
  → Build succeeded. 0 Warning(s)  0 Error(s)
    netstandard2.0, net8.0, net10.0 (library) + net8.0, net10.0 (tests)

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  → Test run summary: Passed!
    total: 16162   failed: 0   succeeded: 16162   skipped: 0
```

No test was added: this phase changes packaging metadata only, and there is no behaviour to assert.
Criterion 1 is instead evidenced by the MSBuild property/item evaluation above, which is the closest
thing to a test the csproj admits short of the pack-verify PHASE04 owns.

## Deviations & follow-ups

- **No deviations from the plan.** Every PHASE01 instruction was followed as written; the two places
  the plan predicted "no change expected" (TFM set, `GenerateDocumentationFile`) both turned out that
  way.
- **`README.md` is still 0 bytes while `PackageReadmeFile` now names it.** This is the plan's
  intended ordering (PHASE03 writes the README, PHASE04 packs), and it does not affect the build —
  readme content is only examined at pack time. It does mean **`dotnet pack` should not be run
  between now and PHASE03**: it would at best embed an empty README, which is exactly the silent
  nuget.org landing-page failure PHASE04's pack-verify exists to catch, and NuGet may reject it
  outright. Not a defect; a sequencing constraint.
- **No `origin` remote and no tags exist yet.** `git remote -v` is empty and `git tag` lists nothing,
  so `RepositoryUrl` / `PackageProjectUrl` point at a GitHub repository that is not yet wired up
  locally. Harmless for metadata (both are strings in the nuspec), and PHASE04 already plans to print
  its merge/tag/push steps as conditional in this situation. The empty tag list also confirms the
  plan's tag-format choice: bare `X.Y.Z`, the family default for a repo with no tags.
- **`PackageReleaseNotes` is provisional**, as noted above — PHASE03 must reconcile it with the real
  `RELEASENOTES.md`. Flagged here so it is not mistaken for finished.
- **Line endings:** nothing to report. The diff for this phase is LF-clean, with no CRLF↔LF churn in
  any touched file.
