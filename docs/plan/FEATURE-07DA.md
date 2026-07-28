# FEATURE-07DA — NuGet release preparation (v1.0.0)

**Status:** IN PROGRESS
**Type:** FEATURE (4 phases — the `dotnet-release` **first release** shape)
**Depends on:** FEATURE-11B6 (complete)

## Objective

Take the finished library to a published `Enigma.DataEncryption` 1.0.0 on nuget.org: package
metadata, third-party license audit, per-category guides, the packed README and release notes,
community files, the release runbook, a local pack-verify, and the printed publish runbook.

## Execution boundary (from `dotnet-release`)

**In-repo edits only.** Exactly two run-permitted exceptions, both local and reversible:

- The **pack-verify** below (packs into a throwaway directory, inspects, then deletes it).
- Local GUID generation — **not applicable**: MSI profiles are apps-only, and this is a library with a
  `PackageId`.

**Print, never run:** `git tag`, `git push`, the publish `dotnet pack` into `./artifacts`,
`dotnet nuget push`, and the merge of `develop` into `main`. The NuGet API key is never stored,
committed, or echoed.

## Phase overview

| Phase | Title | Suggested branch |
|---|---|---|
| PHASE01 | Package metadata & build config + license audit | `feature/feature-07da-phase01-metadata` |
| PHASE02 | Per-category guides & index | `feature/feature-07da-phase02-guides` |
| PHASE03 | README + release notes + community files | `feature/feature-07da-phase03-readme` |
| PHASE04 | Release runbook, pack-verify & final cut prep | `feature/feature-07da-phase04-runbook` |

The ordering is fixed by two constraints: there is nothing valid to pack until the metadata exists, so
pack-verify cannot move earlier; and the README's *Documentation* section summarises the guides, so
writing it first means writing it twice.

---

## PHASE01 — Package metadata & build config + license audit

**Status:** DONE — see `docs/done/FEATURE-07DA-PHASE01.md`

### Package metadata — all 12 properties in `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj`

| # | Property | Value |
|---|---|---|
| 1 | `PackageId` | `Enigma.DataEncryption` |
| 2 | `Version` | `1.0.0` |
| 3 | `Title` | `Enigma.DataEncryption — Stream Encryption for .NET` |
| 4 | `Description` | One paragraph: stream-based authenticated encryption on Enigma.Core; PBKDF2 / Argon2id password, RSA-OAEP, and post-quantum ML-KEM (512/768/1024) key establishment; AES-256, Twofish-256, Serpent-256, Camellia-256 in GCM; self-describing binary format with an authenticated header and a key-confirmation tag; DI-friendly |
| 5 | `PackageTags` | `enigma encryption decryption cryptography stream aes gcm twofish serpent camellia rsa oaep ml-kem post-quantum pbkdf2 argon2 dotnet` |
| 6 | `PackageReadmeFile` | `README.md` |
| 7 | `PackageLicenseFile` | `LICENSE.md` |
| 8 | `RepositoryUrl` | `https://github.com/enigmalibs/Enigma.DataEncryption` |
| 9 | `RepositoryType` | `git` |
| 10 | `PackageProjectUrl` | `https://github.com/enigmalibs/Enigma.DataEncryption` |
| 11 | `PackageReleaseNotes` | Prose mirroring the top of `RELEASENOTES.md`, ending `See RELEASENOTES.md for the full details.` (written in PHASE03; a placeholder here is acceptable only if PHASE03 replaces it) |
| 12 | `GenerateDocumentationFile` | `true` — already set by FEATURE-67FD; verify |

Plus the two structural requirements:

```xml
<ItemGroup>
  <None Include="..\..\README.md" Pack="true" PackagePath="\" />
  <None Include="..\..\LICENSE.md" Pack="true" PackagePath="\" />
</ItemGroup>
```

and **`GeneratePackageOnBuild` absent or `false`** — the package is packed explicitly by the release
step, never on every local build.

### Target-framework normalization

Current set: `netstandard2.0;net8.0;net10.0`. This is **already** the normalized result — `netstandard*`
preserved, plain-`net` targets exactly the current LTS pair. **No change expected.** Confirm and record
"already normalized, no change" in the completion doc; if it somehow differs, propose → confirm → log
before editing, since a TFM change moves the compatibility surface.

### Symbols & SourceLink

**Not enabled.** `dotnet pack` produces only the `.nupkg`, consistent with Enigma.Core. Record this as
a deliberate decision so a later reader does not mistake it for an oversight. Do not claim a `.snupkg`
exists anywhere in the docs.

### Third-party license audit

Audit **what ships** — runtime dependencies only:

| Dependency | Kind | Ships? | License |
|---|---|---|---|
| `Enigma.Core` 1.0.0 | runtime, all TFMs | **yes** | MIT (verify at `LICENSE.md` in the repo/package) |
| `Microsoft.Extensions.DependencyInjection.Abstractions` | runtime, all TFMs | **yes** | MIT |
| `BouncyCastle.Cryptography` 2.6.2 | runtime, transitive via Enigma.Core | **yes** | MIT |
| `System.Buffers` | runtime, `netstandard2.0` only | **yes** | MIT |
| `PolySharp` | compile-only, `PrivateAssets=all` | no | MIT (not redistributed) |
| `xunit.v3`, `coverlet.collector` | test-only | no | out of scope |

Confirm each shipping dependency's license permits redistribution, and that this package's own
`LICENSE.md` is present, correct, and packed. **Record the findings in the completion doc.** This step
is first-release only.

### Acceptance criteria (PHASE01)

1. All 12 properties present and correct; packing `ItemGroup` present; `GeneratePackageOnBuild` off.
2. TFM set confirmed already normalized, recorded.
3. License audit table completed in the completion doc, every shipping dependency verified.
4. Zero-warning Release build; full suite still green. (A "metadata" phase still touches the csproj —
   keep the build green.)

---

## PHASE02 — Per-category guides & index

**Status:** DONE — see `docs/done/FEATURE-07DA-PHASE02.md`

### Guides — `docs/guides/`

One guide per category the library actually has — six, following the shape of
`~/.claude/skills/dotnet-release/templates/guide.md` (intro → supported operations table → key types
table → `###`-per-scenario usage → notes):

| File | Covers |
|---|---|
| `password-based.md` | `IPbkdf2DataEncryptionService`, `IArgon2DataEncryptionService`; cost parameters and how to choose them; `byte[]` vs `char[]` passwords and clearing them |
| `rsa.md` | `IRsaDataEncryptionService`; generating a key pair with Enigma.Core's `IPublicKeyService`; PEM handling; encrypted private-key PEMs and `keyPassword` |
| `ml-kem.md` | `IMLKemDataEncryptionService`; the three parameter sets and how to choose; generating and **persisting** ML-KEM keys (they are raw `byte[]`, so the documented pattern is to protect the private key at rest by encrypting it with this library's own password service) |
| `header-inspection.md` | `IEncryptedDataInspector`, `EncryptedDataHeader`, the detect-then-dispatch pattern, and the seekable/non-seekable position behaviour |
| `file-operations.md` | `DataEncryptionFileExtensions`; the three documented semantics (async `FileStream`, create-or-overwrite, partial output deleted on failure) |
| `dependency-injection.md` | `AddEnigmaDataEncryption()`, what it registers including the Enigma.Core factories, singleton lifetimes, `TryAdd*` override behaviour, and manual registration for non-DI consumers |

Index: `docs/guides/README.md` from
`~/.claude/skills/dotnet-release/templates/guides-README.md` — themed groups of **relative** links.
Relative links between guides are correct here, because this index is **not** packed.

The index must also point at **`../format.md`** as the normative binary-format specification, framed as
"the spec; the guides are usage". Do not duplicate the format tables into the guides.

### Delegation

The six guides are independent and split cleanly → **one sub-agent per guide**, each given its target
path and the relevant public API surface. Per `dev-workflow`: sub-agents write content only; all git
actions, roadmap/plan/`done` updates and commit messages stay with the owner, who integrates and
re-verifies every snippet before the phase is done.

### The snippet-verification gate — required

There is **no compile harness for doc snippets**, so this gate is the only thing that catches drift:

- Cross-check **every** API reference in **every** code fence against the real public surface in
  `src/`: `using` namespaces, type names, method names and argument shapes (including `async`/`await`
  and optional-parameter names), enum members, static constants, extension methods.
- Also cross-check every **Enigma.Core** symbol used in the guides (`IPublicKeyService.GenerateRsaKeyPair`,
  `IMLKemService.GenerateKeyPair`, `MLKemParameterSet`, …) — the RSA and ML-KEM guides necessarily show
  key generation, which is Enigma.Core's API, not ours.
- Fix every mismatch in place.
- **Record coverage in the completion doc as a table** — per file: *snippets · symbols · mismatches ·
  uncertain*, with totals. (Enigma.Core's polish pass recorded 60 snippets / 209 symbols / 0
  mismatches; the table is what makes the claim auditable.)

A permanent doc-sample test project is the known alternative; Enigma.Core considered and declined it,
and it is **not** required here.

### Acceptance criteria (PHASE02)

1. Six guides plus the index exist, following the template shape.
2. The index links `../format.md` as the normative spec; no format tables duplicated into guides.
3. Snippet-verification gate run; coverage table in the completion doc; **zero** mismatches remaining.
4. Every guide's snippets verified against both this library's and Enigma.Core's real public surface.
5. Zero-warning Release build; full suite still green.

---

## PHASE03 — README + release notes + community files

**Status:** TODO

### `README.md` (repo root — **packed**, and the nuget.org landing page)

From `~/.claude/skills/dotnet-release/templates/package-README.md`. Section order: title → badges →
one-paragraph intro → what's-new callout → *Features* → *Installation* → *Quick start* →
*Documentation* → *License*. **Summary length** — the guides carry the detail.

Badges — exactly the house set of two, in this order, and **no Downloads badge** (on a fresh package it
advertises a low count):

```markdown
[![NuGet](https://img.shields.io/nuget/v/Enigma.DataEncryption.svg)](https://www.nuget.org/packages/Enigma.DataEncryption)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)
```

What's-new callout:

```markdown
> **What's new in 1.0** — <one-line highlight>. See [RELEASENOTES.md](RELEASENOTES.md).
```

Installation must carry the supported-frameworks line: targets **netstandard2.0, net8.0, net10.0**;
built on Enigma.Core 1.0.0.

**Link rule — a correctness constraint, not a style preference.** The README is packed and renders on
nuget.org where the repository tree does not exist:

- Link **only** to packed or repo-root files — `LICENSE.md`, `RELEASENOTES.md`.
- Point at the guides **and at `docs/format.md`** in prose — name where they live (`docs/guides/`,
  indexed by `docs/guides/README.md`) and what they cover. **No clickable per-guide links, no link to
  `docs/format.md`.**
- **No absolute GitHub URLs** — they hard-code org/repo/branch and rot on a rename.

*Features* should say what genuinely distinguishes this library, all of it true of the implementation:
four credential types including post-quantum ML-KEM; four GCM ciphers; a self-describing format whose
**header is authenticated as AAD**; a **key-confirmation tag** giving fast wrong-credential failure and
key commitment; documented **caps on attacker-controlled header values**; stream-based with
`IProgress<int>` and `CancellationToken`; DI-friendly with one registration call.

### `RELEASENOTES.md` (repo root)

From the template's **first-release** variant: *Feature overview · Compatibility · Version*.

- Compatibility: `netstandard2.0;net8.0;net10.0`; no TFM was dropped (first release).
- Say explicitly that the binary format is **not** compatible with
  `Enigma.Cryptography.DataEncryption`, and why (authenticated header, key-confirmation tag,
  OAEP-SHA256 key wrap, Argon2 memory recorded in KiB). Point at the reserved version range
  `0x01`–`0x0F` as the mechanism by which a future release could read old files.
- No `CHANGELOG.md` — `RELEASENOTES.md` is the single release-notes source.

### `PackageReleaseNotes`

Update property 11 in the csproj to prose mirroring the top of `RELEASENOTES.md`, ending
`See RELEASENOTES.md for the full details.`

### Community files

- **`SECURITY.md`** — **offer** it from `~/.claude/skills/dotnet-release/templates/SECURITY.md`
  (create only if missing). Recommended for a publicly published cryptography package. If accepted,
  fill supported versions, GitHub private vulnerability reporting, what to expect, and scope.
- **No `CONTRIBUTING.md`** unless requested.
- **`LICENSE.md`** — already written at bootstrap; here only **verify** it exists, is referenced by
  `<PackageLicenseFile>`, and is packed.
- **`CLAUDE.md`** — not a release artifact. It is covered by the documentation-freshness sweep.

### Acceptance criteria (PHASE03)

1. `README.md` follows the template section order, carries exactly the two house badges, the what's-new
   callout, and the supported-frameworks line.
2. **No relative `docs/…` link and no absolute GitHub URL anywhere in `README.md`** — verified by
   grepping the file, not by eye.
3. `RELEASENOTES.md` first-release section complete, including the explicit
   not-compatible-with-the-predecessor statement.
4. `PackageReleaseNotes` mirrors the top of `RELEASENOTES.md` and ends with the required sentence.
5. `SECURITY.md` offered; created if accepted.
6. No `CHANGELOG.md` in the repo.
7. If the README quick-start contains code, the snippet-verification gate is re-run over it and the
   coverage recorded.
8. Zero-warning Release build; full suite still green.

---

## PHASE04 — Release runbook, pack-verify & final cut prep

**Status:** TODO

### `docs/RELEASE.md`

From `~/.claude/skills/dotnet-release/templates/RELEASE.md` (create only if missing), placeholders
filled: `{{PACKAGE_ID}}` → `Enigma.DataEncryption`, `{{SOLUTION}}` → `Enigma.DataEncryption.slnx`,
`{{LIB_CSPROJ}}` → `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj`, `{{LIB_DIR}}` →
`src/Enigma.DataEncryption`, `{{DEFAULT_BRANCH}}` → `main`.

The template's step-5 wording assumes **no symbols** — which matches PHASE01's decision, so no
adjustment is needed.

### Pre-flight

```bash
dotnet build Enigma.DataEncryption.slnx -c Release
dotnet test --solution Enigma.DataEncryption.slnx -c Release
```

### Pack-verify (local, then deleted)

```bash
dotnet pack src/Enigma.DataEncryption/Enigma.DataEncryption.csproj -c Release -o ./artifacts-verify
```

Inspect the `.nupkg` and the nuspec inside it, and confirm:

- the **`.nupkg` version** is `1.0.0`;
- **`README.md` is embedded and non-empty** — an empty packed README is a silent nuget.org landing-page
  failure, and this repo's README started life as a 0-byte placeholder, so this check matters here more
  than usual;
- **`LICENSE.md` is embedded**;
- the nuspec's `<version>`, `<title>`, `<license type="file">`, `<readme>` and `<releaseNotes>` are all
  correct;
- **dependency floors per target framework** are what you expect — `Enigma.Core` and
  `Microsoft.Extensions.DependencyInjection.Abstractions` on all three TFMs, `System.Buffers` on
  `netstandard2.0` only, and **`PolySharp` absent** (it is compile-only, `PrivateAssets=all`);
- the XML documentation file ships for each TFM.

Then **delete `./artifacts-verify`** — it is scratch and never committed.

### Printed runbook (print; the user runs it)

Detected specifics for this repo: tag format **bare `X.Y.Z`** (matching `Enigma.Core`'s `1.0.0` and the
predecessor's `1.2.0`); default branch **`main`**; solution file **`Enigma.DataEncryption.slnx`**.

```bash
# 1. Pre-flight (Release configuration)
dotnet build Enigma.DataEncryption.slnx -c Release
dotnet test  --solution Enigma.DataEncryption.slnx -c Release

# 2. Merge the release branch into develop, then develop into main; then locally:
git switch main && git pull

# 3. Tag (bare X.Y.Z, matching the family convention)
git tag 1.0.0
git push origin 1.0.0

# 4. Pack (GeneratePackageOnBuild is off)
dotnet pack src/Enigma.DataEncryption/Enigma.DataEncryption.csproj -c Release -o ./artifacts

# 5. Push to NuGet (API key has push rights; never commit or echo it)
dotnet nuget push ./artifacts/Enigma.DataEncryption.1.0.0.nupkg \
  --api-key <NUGET_API_KEY> \
  --source https://api.nuget.org/v3/index.json
```

Post-publish verification to print alongside: the package page shows `1.0.0`; the README NuGet badge
resolves; `dotnet add package Enigma.DataEncryption --version 1.0.0` restores; and the `1.0.0` tag
exists with notes matching `RELEASENOTES.md`.

**Note:** the merge/tag/push steps assume the GitHub repository at
`https://github.com/enigmalibs/Enigma.DataEncryption` exists and `origin` is configured. If it does
not yet, say so plainly and print the steps as conditional rather than pretending they are runnable.

### Acceptance criteria (PHASE04)

1. `docs/RELEASE.md` exists with every placeholder filled.
2. Pre-flight build and test both clean in Release.
3. Pack-verify performed and **every** checklist item above confirmed against the actual artifact;
   `./artifacts-verify` deleted afterwards.
4. The runbook is **printed, not run**. No tag created, no pack into `./artifacts`, no push.
5. No NuGet API key appears in the repo or in any output.
6. Findings from the pack-verify recorded in the completion doc.

---

## Notes for the implementer

- A doc-only phase still keeps the Release build green whenever it touches the csproj —
  `PackageReleaseNotes` and `Description` are csproj edits even in a "documentation" phase.
- The documentation-freshness sweep (`dev-workflow`) runs at the end of **every** phase of this item,
  and `CLAUDE.md` is a prime candidate — it was written at bootstrap describing a library with no
  implementation.
- Do not add a Downloads badge, a `CHANGELOG.md`, or a symbol package. Each is an explicit non-choice
  recorded above, not an omission.
