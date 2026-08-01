# FEATURE-4A67-PHASE02 — Release v1.1.0

**Status:** DONE
**Branch:** `feature/feature-4a67-phase02-release-110`
**Plan:** `docs/plan/FEATURE-4A67.md` (PHASE02)

## Summary

Cut **v1.1.0** — the release-preparation half of `FEATURE-4A67`, following `dotnet-release`'s **routine
release** path (a published version already exists, so the 12 packaging properties and the third-party
licence audit are not redone). The version moved to 1.1.0, the release notes and package metadata were
written, the README/SECURITY/CLAUDE surfaces were made consistent at 1.1.0, and the artifact was packed once
into a throwaway directory and inspected before that directory was deleted.

Beyond the version mechanics, this phase **corrected a stale narrative that had become actively misleading**:
`CLAUDE.md` and `docs/roadmap.md` both still told every future agent that v1.0.0 was unpublished and the
pre-publication format window was open — i.e. that header changes were still free. They have not been since
2026-07-31.

**Nothing was tagged, packed for publication, or pushed.** The runbook is printed for the maintainer.

## Version & package metadata

| Item | From | To |
|---|---|---|
| `<Version>` (library csproj) | 1.0.0 | **1.1.0** |
| `<PackageReleaseNotes>` | first-release prose | rewritten to mirror the new `RELEASENOTES.md` section |

The `PackageReleaseNotes` prose still ends `See RELEASENOTES.md for the full details.` — it and the notes
file are duplicated prose kept in step by hand, as the csproj comment says. Confirmed unchanged in passing:
all 12 packable-library properties present, `GeneratePackageOnBuild` still **absent**, and none of
`IncludeSymbols` / `SymbolPackageFormat` / `PublishRepositoryUrl` / `EmbedUntrackedSources` has crept in — a
release ships exactly one file.

**No target-framework change.** `netstandard2.0;net8.0;net10.0` is already the normalized set (every
`netstandard` target preserved, the modern-.NET pair at `net8.0;net10.0`), so there was nothing to propose
and nothing to log as a compatibility note. BouncyCastle 2.7.0 still ships `netstandard2.0`.

## `RELEASENOTES.md`

A v1.1.0 section prepended above the 1.0.0 one, which is **preserved unmodified** — including its
"Built on **Enigma.Core 1.0.0**" line, which is a dated statement of what was true then (decision 11).

Two sub-sections, both non-empty, in the template's order:

- **Dependencies** — `Enigma.Core 1.0.0 → 1.1.0` raising **BouncyCastle.Cryptography 2.6.2 → 2.7.0**
  transitively; `Microsoft.Extensions.DependencyInjection.Abstractions` **held at 9.0.18** with the reason;
  and the test-only, never-redistributed `coverlet.collector 6.0.4 → 10.0.1` and
  `Microsoft.Testing.Extensions.CodeCoverage 18.0.4 → 18.0.6`.
- **Compatibility** — no public API change; target frameworks unchanged; the **BouncyCastle floor now
  2.7.0**, so consumers pinned to 2.6.x must upgrade (the one consumer-visible floor this release moves, and
  the reason it is 1.1.0 rather than a patch); the **container format unchanged**, with the 24 committed
  1.0.0-era fixtures cited as the evidence; and the **PEM exception-type behaviour change**, stated plainly
  together with why it is *not* a breaking change — `docs/format.md` §9 always permitted both types, so only
  which branch fires has changed.

No *New Features*, *Fixes* or *Breaking Changes & Migration* sub-section (decision 6). The notes do tell a
reader catching `FormatException` alone to widen the clause, which is the practical consequence without
overstating it as a break.

## Documentation consistency

| File | Change |
|---|---|
| `README.md` | What's-new callout `1.0` → **1.1** with a one-line highlight; *Installation* line `built on Enigma.Core 1.0.0` → **1.1.0** |
| `SECURITY.md` | Supported-versions table `1.0.x` → **1.1.x** (latest released version only, per the existing policy text) |
| `CLAUDE.md` | Runtime dependency → **Enigma.Core 1.1.0** (noting the transitive BouncyCastle 2.7.0 floor); the stale-narrative correction; a §9 note on which exception branch now fires |
| `docs/roadmap.md` | The same narrative correction, in two paragraphs |
| `docs/RELEASE.md` | Tag-convention sentence — the optional edit, **made**; see below |

Untouched, as the plan requires: `README.md`'s badges (the NuGet-version badge self-tracks; there is no
Downloads badge in the house set) and its supported-TFM line (the TFM set did not move); the six guides
other than `rsa.md`/`hybrid.md`, which name no package version — and those two were handled in PHASE01, so
**the snippet-verification gate did not fire again in this phase**. No `CHANGELOG.md` was added:
`RELEASENOTES.md` is the single release-notes source. No `src/` change beyond the csproj version and notes.

### The stale-narrative correction

This was the substantive documentation work, not a version-string sweep. Both files asserted, as present
tense, that v1.0.0 was *"prepared but not published"* and that *"publishing closes that window"* — a future
event. `docs/roadmap.md` additionally stated that **"v1.0.0 is published only after that item's triage"**,
naming `FEATURE-F612` as a gate on first publication. All of it was overtaken on 2026-07-31.

The correction states the facts: v1.0.0 **was published on 2026-07-31** and is tagged bare `1.0.0`; the
format window is **closed**, so a further header change now costs a format-version bump or a new method
byte; and `FEATURE-F612` is a **post-release** audit whose report mints a `CODE-REVIEW` item shipping in a
later 1.x — not a gate on a first publication. The code-freeze statement about F612 was **kept**, because it
is still true. The historical framing of why `FEATURE-5A30` and `FEATURE-0D64` were cheap is kept too, but
re-tensed to the past.

One thing was added rather than merely corrected: both files now say the 24 committed fixtures **are** the
cross-version compatibility evidence, and point at PHASE01 as the worked example. That is the practical
consequence of the window closing, and it is the part a future agent most needs.

`CLAUDE.md` also gained a §9 note recording that although the spec permits `ArgumentException` *or*
`FormatException` for an unparseable PEM, only `ArgumentException` now fires — so §9 reads as *what is
permitted*, not *what happens*.

### `docs/RELEASE.md` — the optional edit was **made**

The plan left this to the builder's discretion and asked for a statement either way. The tag-convention
sentence cited Enigma.Core and the predecessor as the precedent for bare `X.Y.Z`; this repository now has
its own `1.0.0` tag, so it cites itself first and the family second. Cosmetic, and it makes the runbook
self-contained.

The plan's design step 7 was confirmed correct: `docs/RELEASE.md`'s dependency-floor table lists **package
names only, with no versions**, so nothing there needed refreshing for the Enigma.Core bump.

## Files touched

**Modified:** `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj`, `RELEASENOTES.md`, `README.md`,
`SECURITY.md`, `CLAUDE.md`, `docs/RELEASE.md`, `docs/roadmap.md`, `docs/plan/FEATURE-4A67.md`.
**Created:** this file. **Deleted:** `./artifacts-verify/` (scratch, never committed).

## Build/test evidence

Re-verified in this phase, not carried over from PHASE01:

- `dotnet build Enigma.DataEncryption.slnx -c Release --no-incremental` → **Build succeeded, 0 Warning(s),
  0 Error(s)** on `netstandard2.0`, `net8.0` and `net10.0`.
- `dotnet test --solution Enigma.DataEncryption.slnx -c Release` → **total 28,272 · failed 0 · succeeded
  28,272 · skipped 0**, both test TFMs.

### Pack-verify

`dotnet pack src/Enigma.DataEncryption/Enigma.DataEncryption.csproj -c Release -o ./artifacts-verify`,
inspected, then **deleted**. Every point of the plan's design step 8:

| Check | Result |
|---|---|
| `.nupkg` version | `Enigma.DataEncryption.1.1.0.nupkg` ✔ |
| Directory holds the `.nupkg` and nothing else | ✔ — no `.snupkg` |
| `README.md` embedded, non-empty, and the **updated** one | ✔ — 6,045 bytes; carries "What's new in 1.1" and "built on Enigma.Core 1.1.0" |
| `LICENSE.md` embedded | ✔ — 1,061 bytes |
| nuspec `<version>` / `<title>` / `<license type="file">` / `<readme>` / `<releaseNotes>` | ✔ all correct |
| `lib/{netstandard2.0,net8.0,net10.0}` `.dll` + `.xml` | ✔ all six files present |
| `PolySharp` absent from every dependency group | ✔ — absent from the nuspec entirely |

Dependency floors, per target framework:

| Target framework | Dependencies in the nuspec |
|---|---|
| `net8.0` | `Enigma.Core >= 1.1.0`, `Microsoft.Extensions.DependencyInjection.Abstractions >= 9.0.18` |
| `net10.0` | `Enigma.Core >= 1.1.0`, `Microsoft.Extensions.DependencyInjection.Abstractions >= 9.0.18` |
| `.NETStandard2.0` | the same two, plus `System.Buffers >= 4.6.1` |

Exactly as specified. Note what is **not** there: no `coverlet.collector` and no
`Microsoft.Testing.Extensions.CodeCoverage`, confirming that PHASE01's test-tooling bumps do not reach
consumers.

## Deviations & follow-ups

1. **The `docs/roadmap.md` correction went one paragraph further than the plan named.** Design step 6
   pointed at the paragraph claiming v1.0.0 "is prepared but not published". A second paragraph — the
   `FEATURE-F612` ordering note — separately asserted that **"v1.0.0 is published only after that item's
   triage"**. Acceptance criterion 4 requires that neither file still claim v1.0.0 is unpublished, so that
   paragraph was corrected too. Not a change of direction; the plan's criterion is what drove it.

2. **The optional `docs/RELEASE.md` edit was made**, as recorded above. The plan required stating which.

   **Documentation freshness sweep** added one further `CLAUDE.md` edit: its opening *Current state*
   paragraph still read "One planned item now stands between the library and the release — `FEATURE-F612`",
   which the corrections above contradicted from further down the same file — and it is the first thing an
   agent reads. It now states that v1.0.0 shipped on 2026-07-31, that `FEATURE-4A67` prepared v1.1.0, and
   that F612 is a post-release audit. Nothing else was stale: `docs/guides/README.md` carries no version
   references, and the six untouched guides name no package version.

3. **`FEATURE-F612` merge conflict expected and accepted** (decision 9). Its PHASE01–PHASE03 branches are
   unmerged, and this phase rewrote roadmap prose that those branches also touch. New rows are appended
   last, so the overlap is confined to the ordering-notes prose. **Resolve at merge time**, keeping this
   phase's corrected publication facts — F612's branches predate the correction and will reintroduce the
   stale claim if taken wholesale.

4. **Release stops at pack-verify** (decision 10). The tag, the publish `dotnet pack` into `./artifacts`,
   and `dotnet nuget push` are **printed only**. The NuGet API key appears nowhere in the repository or in
   any output.

5. **Carried forward from PHASE01, still open:** the cross-repo follow-up to correct Enigma.Core 1.1.0's
   release-notes claim that "the library's own behaviour is unchanged" and add a characterization test for
   the invalid-Base64 PEM case; and revisiting `Microsoft.Testing.Extensions.CodeCoverage` once `xunit.v3`
   4.x is stable (the 18.0.x cap is an MTP v1/v2 constraint, documented in `Directory.Packages.props` and
   `CLAUDE.md`). Neither blocks this release.

6. **Deferred again, deliberately** (decision 3): dropping `coverlet.collector`, and bumping
   `Microsoft.Extensions.DependencyInjection` / `.Abstractions` to the 10.x line. The next release has to
   decide about both again.

7. **Line endings:** no CRLF/LF noise observed; every file touched is LF. No action taken
   (recommendation-only per `dev-workflow`).

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | `<Version>1.1.0</Version>` and `<PackageReleaseNotes>` mirroring the notes, ending with the pointer sentence | Met |
| 2 | `RELEASENOTES.md` v1.1.0 section — *Dependencies* + *Compatibility* only, all three transitions, the held-back MEDI, the raised BouncyCastle floor, the unchanged format, the PEM change; 1.0.0 section preserved | Met |
| 3 | `README.md`, `SECURITY.md`, `CLAUDE.md` consistent at 1.1.0 / Enigma.Core 1.1.0; badges and TFM list unchanged | Met |
| 4 | `CLAUDE.md` and `docs/roadmap.md` no longer claim v1.0.0 is unpublished or the window open; both state the date and the consequence | Met |
| 5 | Release build 0 warnings on all three TFMs; full suite green on both test TFMs, re-verified in this phase | Met |
| 6 | Pack-verify passed on every point; verify directory deleted | Met |
| 7 | Runbook printed, not run; bare `1.1.0` tag format; no API key anywhere | Met |
| 8 | This document written, stating whether the optional `docs/RELEASE.md` edit was made | Met — it was made |
| 9 | The item's roadmap row flips to `DONE` alongside PHASE02, plan statuses with it | Met |
