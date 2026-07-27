# FEATURE-67FD — Repository & solution bootstrap (DONE)

## Summary

Turned the empty `/home/jo/Dev/Enigma.DataEncryption` directory into an initialized git repository
holding a building, testing .NET solution skeleton. Ran `git init -b main`, laid down all 12 root
configuration artifacts in the `dotnet-solution-setup` bootstrap order, and scaffolded an empty
multi-targeted `Enigma.DataEncryption` library plus an MTP-native xUnit v3 test project with a single
smoke test. No production code beyond an `AssemblyInfo.cs` — every real type belongs to FEATURE-00E7.

The planning artifacts (`docs/roadmap.md` and the six `docs/plan/*.md` files) predate the repository,
so they are part of this dev's own initial commit rather than a separate earlier planning commit, as
the plan anticipated.

## Files/modules touched

### Created — git & config (verbatim from house templates, `cmp`-verified byte-identical)
- `.gitignore` — from `git-repo-hygiene/templates/gitignore`
- `.gitattributes` — from `git-repo-hygiene/templates/gitattributes` (`* text=auto eol=lf` in force
  from the first commit)
- `.editorconfig` — from `dotnet-solution-config/templates/editorconfig` (the full C# variant, 216
  lines; identical to Enigma.Core's)

### Created — root build config & docs
- `Directory.Build.props` — solution-wide defaults: `Authors`/`Copyright` (Josué Clément, 2026),
  `LangVersion 14`, `Nullable enable`, `ImplicitUsings disable`, `TreatWarningsAsErrors true`,
  `EnforceCodeStyleInBuild true`
- `Directory.Packages.props` — Central Package Management on; central versions for Enigma.Core 1.0.0,
  Microsoft.Extensions.DependencyInjection.Abstractions 9.0.18, System.Buffers 4.6.1, PolySharp
  1.16.0, xunit.v3 3.2.2, coverlet.collector 6.0.4
- `global.json` — SDK `10.0.100` / `rollForward: latestFeature`; `test.runner:
  Microsoft.Testing.Platform`
- `LICENSE.md` — MIT-style house licence, `{{YEAR}}` → 2026, `{{AUTHORS}}` → Josué Clément
- `README.md`, `RELEASENOTES.md` — empty (0 bytes), filled by FEATURE-07DA
- `Enigma.DataEncryption.slnx` — `.slnx` solution referencing both projects under `/src/` and `/tests/`
- `CLAUDE.md` — agent guidance: current state, planned four-service architecture, the
  BouncyCastle-isolation invariant, project layout, TFMs & dependencies, build/test commands,
  conventions, dev-workflow summary

### Created — projects
- `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj` — library, `netstandard2.0;net8.0;net10.0`,
  `GenerateDocumentationFile=true`; `Enigma.Core` + `Microsoft.Extensions.DependencyInjection.Abstractions`
  on all TFMs; `System.Buffers` + `PolySharp` (`PrivateAssets=all`) conditional on netstandard2.0 only;
  **no** packaging metadata
- `src/Enigma.DataEncryption/Properties/AssemblyInfo.cs` —
  `[assembly: InternalsVisibleTo("Enigma.DataEncryption.UnitTests")]`, added now so no later dev has to
  touch the csproj for the internal `IRandomSource` seam
- `tests/Enigma.DataEncryption.UnitTests/Enigma.DataEncryption.UnitTests.csproj` — MTP-native xUnit v3
  project (`net8.0;net10.0`, `OutputType=Exe`, `xunit.v3` + `coverlet.collector`, ProjectReference to
  the library, fixture copy-glob for `*.csv`/`*.pem`/`*.key`/`*.bin`/`*.txt`)
- `tests/Enigma.DataEncryption.UnitTests/SmokeTest.cs` — single `[Fact]` asserting the library
  assembly loads on each test TFM

### Modified — workflow tracking
- `docs/roadmap.md` — FEATURE-67FD status `TODO` → `IN PROGRESS` → `DONE`
- `docs/plan/FEATURE-67FD.md` — status `TODO` → `IN PROGRESS` → `DONE`
- `docs/done/.gitkeep` — already present from the planning flow; kept so the directory is tracked

## Deviations & follow-ups

- **Plan internal inconsistency (resolved with the maintainer).** The plan header says
  `Suggested branch: feature/feature-67fd-bootstrap`, but Scope §1 and acceptance criterion 1 say
  `git init -b main` with `develop` cut from `main` afterwards. Enigma.Core's actual history confirms
  the latter — its `chore(FEATURE-56AA): bootstrap repository & solution` commit sits directly on
  `main`. Built on `main`, no dev branch; the header line is a template artifact. Every later item
  follows the normal "branch from `HEAD`" rule.
- **`Microsoft.Extensions.DependencyInjection.Abstractions` 9.0.18, not the highest ns2.0-compatible
  version.** The plan table said 9.0.0 and the note said "pick the highest version that still resolves
  on netstandard2.0". 10.0.10 was probed and does resolve (real `lib/netstandard2.0/` asset, clean
  build on all three TFMs), but the maintainer chose the conservative library floor: 9.0.18, the latest
  9.x patch. Rationale — this is a published library, and a 10.0.x floor would push every consumer,
  including net8.0 ones, onto a 10.x transitive, working against the point of multi-targeting for
  reach. The API used (`IServiceCollection`, `TryAdd*`) has been stable since 2.x. Revisit at
  FEATURE-07DA PHASE01, where dependency floors are the natural review point.
- **`coverlet.collector` held at 6.0.4.** Latest stable is 10.0.1 and it builds clean, but 6.0.4 matches
  both the plan table and Enigma.Core, keeping the sibling repos identical. Zero consumer impact
  either way (`PrivateAssets=all`). Follow-up: coverlet 8.0+ added native Microsoft.Testing.Platform
  integration, so a coordinated bump across Enigma.Core and this repo may be worth doing later.
- **Other package versions are the latest stable** and match the plan table exactly: Enigma.Core 1.0.0
  (only published version), System.Buffers 4.6.1, PolySharp 1.16.0, xunit.v3 3.2.2. All verified with
  `dotnet package search` at implementation time.
- **Placeholder file.** The plan suggested "an empty `Enigma.DataEncryption` namespace marker". Used
  `Properties/AssemblyInfo.cs` instead — it makes the project compile *and* carries the required
  `InternalsVisibleTo`, so FEATURE-00E7 has no throwaway marker file to delete.
- **Smoke test is slightly stronger than Enigma.Core's.** Enigma.Core's bootstrap used
  `Assert.True(true)`; this one uses `Assembly.Load(new AssemblyName("Enigma.DataEncryption"))`, per the
  plan's "assert the library assembly loads". Running on both `net8.0` and `net10.0` proves those two
  builds load; `netstandard2.0` is covered by the build succeeding, since it is never a test TFM.
- **`Directory.Build.props` comments.** Kept the template's explanatory comments (dropped only the
  "Fill these in" instruction, now completed) and narrowed one comment from "library, CLI, Desktop,
  tests" to "library and tests" to match this solution. Enigma.Core's equivalent file is comment-free;
  the values are identical in both.
- **`dotnet test` invocation.** On the .NET 10 SDK in MTP mode, `dotnet test <Solution>.slnx` is
  rejected — the solution must be passed as `dotnet test --solution Enigma.DataEncryption.slnx`.
  Documented in `CLAUDE.md`.
- **Line endings (CRLF):** none observed. A repository-wide scan of every `.cs`/`.csproj`/`.props`/
  `.json`/`.md`/`.slnx` and dotfile found zero CR bytes, and `.gitattributes` enforces
  `* text=auto eol=lf` from the first commit. No action taken (recommendation-only per `dev-workflow`).
- **No commit performed**, per the `dev-workflow` "never commit yourself" rule. The repo is initialized
  on `main` with everything untracked; staging and the initial commit are the maintainer's. A suggested
  commit message is printed at the end of the build run.
- **`develop` branch** is to be created from `main` after that commit, matching Enigma.Core's topology.
  Maintainer's action.

## Build/test evidence

- **Build:** `dotnet build Enigma.DataEncryption.slnx -c Release --no-incremental` →
  `Build succeeded. 0 Warning(s) 0 Error(s)`, producing `Enigma.DataEncryption.dll` for
  `netstandard2.0`, `net8.0` and `net10.0`, and `Enigma.DataEncryption.UnitTests.dll` for `net8.0` and
  `net10.0` — five outputs, zero warnings, with `TreatWarningsAsErrors=true` and
  `EnforceCodeStyleInBuild=true` in force.
- **Test:** `dotnet test --solution Enigma.DataEncryption.slnx -c Release` →
  `Test run summary: Passed! total: 2, failed: 0, succeeded: 2, skipped: 0` — the smoke test green on
  both `net8.0` and `net10.0`.
- **Asset resolution verified** from `project.assets.json`: on the `netstandard2.0` target,
  Enigma.Core, `Microsoft.Extensions.DependencyInjection.Abstractions` 9.0.18 and System.Buffers all
  resolve to real `lib/netstandard2.0/` assets (no fallback); PolySharp correctly contributes no
  compile asset. On the `net8.0` target, System.Buffers and PolySharp are absent, confirming the
  conditional `ItemGroup`s work and NU1510 cannot fire.
- **Empty files:** `wc -c README.md RELEASENOTES.md` → both `0` bytes.
- **Template fidelity:** `cmp -s` confirmed `.gitignore`, `.gitattributes` and `.editorconfig` are
  byte-identical to their source templates. No `{{…}}` placeholder survives anywhere in the tree.
- **Convention greps:** no csproj repeats `LangVersion`/`Nullable`/`ImplicitUsings`/
  `TreatWarningsAsErrors`; no `PackageReference` carries a `Version=` attribute; no
  `Microsoft.NET.Test.Sdk` or `xunit.runner.visualstudio` anywhere; the library csproj carries no
  packaging metadata.

## Acceptance criteria — all met

1. ✅ `git init -b main` run. `git status --porcelain` shows exactly the intended untracked set —
   the 11 root artifacts, `docs/`, `src/`, `tests/` — and nothing else; `bin/`/`obj/` are ignored.
2. ✅ All 12 root artifacts exist as specified. `README.md` and `RELEASENOTES.md` are exactly 0 bytes.
3. ✅ `dotnet build Enigma.DataEncryption.slnx -c Release` succeeds with zero warnings across all
   three library TFMs and both test TFMs.
4. ✅ `dotnet test --solution Enigma.DataEncryption.slnx -c Release` runs the smoke test and passes on
   both `net8.0` and `net10.0`.
5. ✅ No csproj repeats `LangVersion`, `Nullable`, `ImplicitUsings` or `TreatWarningsAsErrors`.
6. ✅ No `PackageReference` carries a `Version=` attribute.
7. ✅ No `Microsoft.NET.Test.Sdk` or `xunit.runner.visualstudio` anywhere in the solution.
8. ✅ The library csproj carries no packaging metadata.
9. ✅ `docs/roadmap.md`, `docs/plan/` (6 files) and `docs/done/.gitkeep` are present.
10. ✅ `CLAUDE.md` describes the actual state of the repository — it opens with an explicit
    "this repository is a bootstrap skeleton / there is no production code yet" statement, and every
    forward-looking section is marked as planned and attributed to its work item.
