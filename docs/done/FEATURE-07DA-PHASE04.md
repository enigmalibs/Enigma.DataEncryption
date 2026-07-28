# FEATURE-07DA — PHASE04 — Release runbook, pack-verify & final cut prep

**Status:** DONE
**Branch:** `feature/feature-07da-phase04-runbook` (cut from `f71fe0d`, the PHASE03 commit)
**Plan:** `docs/plan/FEATURE-07DA.md` § PHASE04

## Summary

The last phase of the release item, and the only one whose output is mostly *not* a committed file. It adds
`docs/RELEASE.md` — the reusable runbook for every future version, not just this one — then proves the
package the runbook tells you to push is actually correct, by packing it locally and reading the artifact
rather than trusting the csproj.

The pack-verify found nothing wrong. That is the useful result: all twelve packaging properties added in
PHASE01 land in the nuspec as intended, the README that started life as a 0-byte placeholder is embedded at
its full 5,458 bytes, and the dependency graph per target framework is exactly the intended one — including
the two negatives that are easy to get wrong and invisible without opening the `.nupkg` (`PolySharp` absent,
`System.Buffers` on `netstandard2.0` only).

Nothing was published. No tag was created, no pack into `./artifacts`, no `dotnet nuget push`. Those steps
are printed for the maintainer to run, per the item's execution boundary.

## Files/modules touched

**Created**

- `docs/RELEASE.md` — the runbook, from `~/.claude/skills/dotnet-release/templates/RELEASE.md`, all five
  placeholders filled (`Enigma.DataEncryption`, `Enigma.DataEncryption.slnx`,
  `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj`, `src/Enigma.DataEncryption`, `main`).
- `docs/done/FEATURE-07DA-PHASE04.md` — this record.

**Modified**

- `docs/roadmap.md` — PHASE04 `TODO` → `IN PROGRESS` → `DONE`; the `FEATURE-07DA` item row → `DONE`
  (final phase).
- `docs/plan/FEATURE-07DA.md` — PHASE04 status, and the item header → `DONE (all four phases)`.
- `CLAUDE.md` — documentation-freshness sweep, accepted: the project-layout tree now lists
  `docs/RELEASE.md`, and the dependency chain no longer describes `FEATURE-07DA` as in progress with
  PHASE04 pending (it reads `done — all four phases`, with the maintainer publish step named as the one
  thing outstanding).

**Created then deleted** (never committed)

- `./artifacts-verify/Enigma.DataEncryption.1.0.0.nupkg` — the pack-verify artifact, removed after
  inspection as the plan requires.

No source file, test file or csproj was touched. The library and the suite are byte-for-byte what PHASE03
left behind.

### Three adaptations to the template

All three are the repo asserting itself over generic template wording; none changes what the runbook does.

1. **`dotnet test --solution Enigma.DataEncryption.slnx -c Release`**, not the template's
   `dotnet test {{SOLUTION}}`. On the .NET 10 SDK in Microsoft.Testing.Platform mode the positional form is
   rejected outright — the template's line would fail on first use. The `--solution` flag and the reason for
   it are both in the runbook, since a maintainer hitting the error a year from now will look there.
2. **Step 2 merges through `develop`** (`release branch → develop → main`) rather than straight to the
   default branch, matching the branch topology this repo actually has.
3. **Step 4 carries a dependency-floor table.** The template says "declare the expected dependency floors";
   here the expectation is specific and asymmetric across TFMs, so it is written out — with the two
   negatives called out explicitly, because an absent dependency is the kind of thing an eye slides past.

The template's step-5 no-symbols wording needed no adjustment: it already matches PHASE01's decision.

## Pack-verify findings

`dotnet pack src/Enigma.DataEncryption/Enigma.DataEncryption.csproj -c Release -o ./artifacts-verify`

**Output — exactly one file**, `Enigma.DataEncryption.1.0.0.nupkg` (173,638 bytes). No `.snupkg`, which is
the observable proof that the symbol opt-in has not crept back into the csproj.

| Checklist item (plan § PHASE04) | Result |
|---|---|
| `.nupkg` version is `1.0.0` | ✅ filename `Enigma.DataEncryption.1.0.0.nupkg`; nuspec `<version>1.0.0</version>` |
| `README.md` embedded and **non-empty** | ✅ 5,458 bytes, `diff -q` byte-identical to the repo root README |
| `LICENSE.md` embedded | ✅ 1,063 bytes, `diff -q` byte-identical to the repo root LICENSE |
| nuspec `<version>` | ✅ `1.0.0` |
| nuspec `<title>` | ✅ `Enigma.DataEncryption — Stream Encryption for .NET` (em dash survives the round-trip) |
| nuspec `<license type="file">` | ✅ `LICENSE.md` |
| nuspec `<readme>` | ✅ `README.md` |
| nuspec `<releaseNotes>` | ✅ present, mirrors the top of `RELEASENOTES.md`, ends `See RELEASENOTES.md for the full details.` |
| XML documentation ships per TFM | ✅ three files — `netstandard2.0` 209,430 B, `net8.0` and `net10.0` 172,036 B each |
| `./artifacts-verify` deleted afterwards | ✅ removed; `git status` shows only the intended doc changes |

**Dependency floors per target framework** — all three groups present and correct:

| Group | Dependencies |
|---|---|
| `net8.0` | `Enigma.Core` 1.0.0 · `Microsoft.Extensions.DependencyInjection.Abstractions` 9.0.18 |
| `net10.0` | `Enigma.Core` 1.0.0 · `Microsoft.Extensions.DependencyInjection.Abstractions` 9.0.18 |
| `.NETStandard2.0` | `Enigma.Core` 1.0.0 · `Microsoft.Extensions.DependencyInjection.Abstractions` 9.0.18 · `System.Buffers` 4.6.1 |

- **`PolySharp` absent** from every group ✅ — `PrivateAssets="all"` doing its job; had it leaked, every
  consumer would inherit a compile-time polyfill generator they have no use for.
- **`System.Buffers` on `netstandard2.0` only** ✅ — the asymmetry is deliberate (NU1510 on `net8.0`+).
- No test-only package (`xunit.v3`, `coverlet.collector`) and no concrete
  `Microsoft.Extensions.DependencyInjection` appears anywhere — the library depends on the *Abstractions*
  alone, as intended.

**Two observations worth recording, neither a defect:**

- The nuspec carries `<repository type="git" url="…" commit="f71fe0d…" />`. The `commit` attribute was not
  configured by us — the .NET 8+ SDK bundles SourceLink and populates `RepositoryCommit` by default. It is
  metadata only: no source is embedded, and `pack` still produces the single `.nupkg` the no-symbols
  decision calls for. Left as-is; suppressing it would mean adding csproj properties to *remove* a
  harmless default.
- `<licenseUrl>https://aka.ms/deprecateLicenseUrl</licenseUrl>` sits beside `<license type="file">`. NuGet
  emits that fixed sentinel itself for older-client compatibility whenever a license *file* is used. Not
  ours, not editable, not a problem.

## Runbook: printed, never run

Acceptance criterion 4 held in full — nothing outward-facing was executed. The maintainer-facing runbook was
printed to the console and is committed as `docs/RELEASE.md`.

**`origin` is not configured, and the repo has no tags.** `git remote -v` prints nothing, so steps 2, 3 and
the tag push are **conditional on the GitHub repository at
`https://github.com/enigmalibs/Enigma.DataEncryption` existing and `origin` being added first**. This was
stated plainly in the printed output rather than papered over — the plan asks for exactly that. The absence
of tags also confirms the bare `X.Y.Z` convention as the right default (matching Enigma.Core `1.0.0` and the
predecessor's `1.2.0`), since there is no existing tag to match.

No NuGet API key appears in the repo, in the runbook, or in any console output — `git grep` over the tracked
tree for `nuget[_-]?api[_-]?key` and for the `oy2…` key shape returns nothing outside the `<NUGET_API_KEY>`
placeholder in the runbook and the plan.

## Deviations & follow-ups

- **No deviation from the plan's substance.** The three template adaptations above are recorded as
  adaptations, not deviations: each is required for the runbook to be correct in *this* repo.
- **`artifacts-verify/` is not in `.gitignore`** (only `artifacts/` is). It was deleted, so nothing leaked,
  but the next pack-verify has the same one-step-from-committing-a-173-KB-binary exposure. Two ways out —
  add `artifacts-verify/` to `.gitignore`, or pack into a directory outside the repo. Not done here:
  `.gitignore` is outside this phase's scope, and the choice is the maintainer's.
- **`RELEASENOTES.md` ↔ `PackageReleaseNotes` stay coupled by hand.** PHASE03 set this up and the csproj
  comment says so; the runbook's step 1 now also checks it, which is the closest thing to enforcement that
  exists. A future release that edits one and not the other will ship stale prose to nuget.org.
- **Line endings:** no CRLF/LF inconsistency observed in the files touched this phase. (Recommendation-only
  per `dev-workflow`; no action taken either way.)
- **The publish itself remains outstanding by design.** FEATURE-07DA is release *preparation*; the tag, the
  pack into `./artifacts` and the push are the maintainer's to run from `docs/RELEASE.md`.

## Build/test evidence

Both run in Release from the repository root, on this branch, before the pack-verify:

```
dotnet build Enigma.DataEncryption.slnx -c Release
  → Build succeeded. 0 Warning(s), 0 Error(s).
    netstandard2.0, net8.0, net10.0 (library) + net8.0, net10.0 (tests) all built.

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  → Test run summary: Passed!
    total: 16162 · failed: 0 · succeeded: 16162 · skipped: 0 · duration 19.5s
    net8.0 passed (19.4s) · net10.0 passed (15.3s)
```

`TreatWarningsAsErrors=true` and `EnforceCodeStyleInBuild=true` are in force, so "0 warnings" is enforced by
the build rather than asserted here.

**No tests were added.** This phase adds one prose document and executes a local, reversible pack; there is
no library behaviour to cover, and the packaging assertions it makes are about an artifact `dotnet pack`
produces, not about code. The verification is the pack-verify table above, performed against the real
`.nupkg`.

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | `docs/RELEASE.md` exists with every placeholder filled | ✅ all five filled; no `{{…}}` remains |
| 2 | Pre-flight build and test both clean in Release | ✅ 0 warnings; 16,162/16,162 passing |
| 3 | Pack-verify performed, every checklist item confirmed, `./artifacts-verify` deleted | ✅ see the two tables above |
| 4 | Runbook printed, not run — no tag, no pack into `./artifacts`, no push | ✅ nothing outward-facing executed |
| 5 | No NuGet API key in the repo or in any output | ✅ `git grep` clean; placeholder only |
| 6 | Pack-verify findings recorded in the completion doc | ✅ this document |

With PHASE04 done, **FEATURE-07DA is complete** — and with it the v1.0.0 release preparation. The library is
packable, the artifact has been inspected, and what remains is the maintainer running `docs/RELEASE.md`.
