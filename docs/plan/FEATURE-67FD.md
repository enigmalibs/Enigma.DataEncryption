# FEATURE-67FD — Repository & solution bootstrap

**Status:** DONE
**Type:** FEATURE (single-phase)
**Suggested branch:** `feature/feature-67fd-bootstrap` — **superseded:** built directly on `main` per
Scope §1 / acceptance criterion 1 (`git init -b main`), matching Enigma.Core's topology. See
`docs/done/FEATURE-67FD.md`.

## Objective

Turn the empty `/home/jo/Dev/Enigma.DataEncryption` directory into an initialized git repository
holding a building, testing .NET solution skeleton, with every root configuration artifact in place
and the house documentation structure established. No production code beyond an empty library and a
smoke test.

## Context

This is the first dev of a greenfield solution. The repository does **not** exist yet — `git init`
is part of this item's scope, which makes it the one dev that starts by creating the repository
rather than by branching from an existing `HEAD`.

**Consequence for the workflow:** the planning artifacts (`docs/roadmap.md` and all six
`docs/plan/*.md` files) were written before the repository existed, so they are already on disk as
untracked files when this dev starts. They therefore become part of this dev's own initial commit
rather than a separate earlier planning commit. Set this item's roadmap status to `IN PROGRESS`
as the first change, exactly as for any other dev.

## Scope

### 1. Git initialization

```bash
git init -b main
```

Then, at the end of the dev (after the user has committed), the `develop` branch is created from
`main` — matching the topology of `Enigma.Core` and `Enigma.Cryptography.DataEncryption`. Creating
`develop` and all commits remain the user's actions; the plan only records that this is the intended
topology.

### 2. Root configuration artifacts, in creation order

The order is the `dotnet-solution-setup` **New solution bootstrap** checklist. Every file is
**created only if missing** — none exist yet, so all are created.

| # | Artifact | Source |
|---|---|---|
| 1 | `.gitignore` | `~/.claude/skills/git-repo-hygiene/templates/gitignore` (verbatim) |
| 2 | `.gitattributes` | `~/.claude/skills/git-repo-hygiene/templates/gitattributes` (verbatim) |
| 3 | `.editorconfig` | `~/.claude/skills/dotnet-solution-config/templates/editorconfig` (the **full C#** one, not git-repo-hygiene's minimal variant) |
| 4 | `Directory.Build.props` | `~/.claude/skills/dotnet-solution-config/templates/Directory.Build.props`, placeholders filled: `{{AUTHORS}}` → `Josué Clément`, `{{YEAR}}` → `2026` |
| 5 | `Directory.Packages.props` | `~/.claude/skills/dotnet-solution-config/templates/Directory.Packages.props`, reduced to the groups this solution needs (see below) |
| 6 | `global.json` | Written directly (four lines, see below) |
| 7 | `LICENSE.md` | `~/.claude/skills/dotnet-solution-setup/templates/LICENSE.md`, `{{YEAR}}` → `2026`, `{{AUTHORS}}` → `Josué Clément` |
| 8 | `README.md`, `RELEASENOTES.md` | Created **empty (0 bytes)** — filled by FEATURE-07DA |
| 9 | `Enigma.DataEncryption.slnx` | `~/.claude/skills/dotnet-solution-setup/templates/Solution.slnx`, `{{PROJECT}}` → `Enigma.DataEncryption` |
| 10 | `src/` + `tests/` projects | See below |
| 11 | `docs/roadmap.md`, `docs/plan/`, `docs/done/` | Already written by the planning flow; add `docs/done/.gitkeep` so the empty directory is tracked |
| 12 | `CLAUDE.md` | Written directly (see below) |

`Directory.Build.props` carries the solution-wide defaults — `LangVersion 14`, `Nullable enable`,
`ImplicitUsings disable`, `TreatWarningsAsErrors true`, `EnforceCodeStyleInBuild true`, `Authors`,
`Copyright`. **No project csproj repeats any of them.**

`Directory.Packages.props` content:

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <!-- Library -->
  <ItemGroup>
    <PackageVersion Include="Enigma.Core" Version="1.0.0" />
    <PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="9.0.0" />
    <PackageVersion Include="System.Buffers" Version="4.6.1" />
    <PackageVersion Include="PolySharp" Version="1.16.0" />
  </ItemGroup>
  <!-- Tests (MTP-native: xunit.v3 only; coverlet.collector for coverage). No Microsoft.NET.Test.Sdk. -->
  <ItemGroup>
    <PackageVersion Include="xunit.v3" Version="3.2.2" />
    <PackageVersion Include="coverlet.collector" Version="6.0.4" />
  </ItemGroup>
</Project>
```

Verify the latest stable versions at implementation time (`dotnet package search`) and record any
deviation from the versions above in the completion doc. `Microsoft.Extensions.DependencyInjection.Abstractions`
must resolve on `netstandard2.0` — pick the highest version that still does.

`global.json`:

```json
{
  "sdk": { "version": "10.0.100", "rollForward": "latestFeature" },
  "test": { "runner": "Microsoft.Testing.Platform" }
}
```

### 3. Library project — `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj`

From `~/.claude/skills/dotnet-solution-setup/templates/library.csproj`, `{{PROJECT}}` →
`Enigma.DataEncryption`. Target frameworks `netstandard2.0;net8.0;net10.0` (mirroring Enigma.Core so
no consumer of Enigma.Core is excluded from this library).

Requirements:

- `<GenerateDocumentationFile>true</GenerateDocumentationFile>`.
- `<PackageReference Include="Enigma.Core" />` and
  `<PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" />`, both on all
  TFMs, **no `Version=` attribute** (Central Package Management).
- `System.Buffers` and `PolySharp` (`PrivateAssets="all"`) referenced **only** under
  `Condition="'$(TargetFramework)' == 'netstandard2.0'"` — an unconditional `System.Buffers`
  reference raises **NU1510** and fails the zero-warnings build.
- `[assembly: InternalsVisibleTo("Enigma.DataEncryption.UnitTests")]` — declared here (in an
  `AssemblyInfo.cs` or via an `ItemGroup` `AssemblyAttribute`) because the internal `IRandomSource`
  seam introduced in FEATURE-00E7 depends on it. Add it now so no later dev has to touch the csproj
  for it.
- **No packaging metadata** (`PackageId`, `Version`, `Description`, …) — that is added at release
  time by FEATURE-07DA PHASE01, per the `dotnet-release` skill.

A single placeholder file is enough to make the project compile — e.g. an empty
`Enigma.DataEncryption` namespace marker. Do **not** pre-create the real types; they belong to
FEATURE-00E7.

### 4. Test project — `tests/Enigma.DataEncryption.UnitTests/Enigma.DataEncryption.UnitTests.csproj`

From `~/.claude/skills/dotnet-solution-setup/templates/test.csproj`, `{{PROJECT}}` →
`Enigma.DataEncryption`.

- `<TargetFrameworks>net8.0;net10.0</TargetFrameworks>` — mirrors the library's modern TFMs so the
  `net8.0` code paths (and the `netstandard2.0` polyfill surface reachable through them) are actually
  exercised. `netstandard2.0` is never a test TFM.
- `<OutputType>Exe</OutputType>` — v3 test projects are executables; `Main` is generated.
- `xunit.v3` + `coverlet.collector` (`PrivateAssets="all"`). **No `Microsoft.NET.Test.Sdk`, no
  `xunit.runner.visualstudio`** — both break the Microsoft Testing Platform.
- `ProjectReference` to the library.
- Keep the template's fixture copy-glob `ItemGroup` (`**/*.bin`, `**/*.pem`, `**/*.key`, `**/*.csv`,
  `**/*.txt` → `CopyToOutputDirectory=PreserveNewest`) — FEATURE-11B6's golden-vector fixtures depend
  on it existing.
- One smoke test proving the harness runs, e.g. asserting the library assembly loads and its
  `netstandard2.0`/`net8.0`/`net10.0` build is reachable.

### 5. `CLAUDE.md`

Modelled on `/home/jo/Dev/Enigma.Core/CLAUDE.md`, covering: what the library is, the four-service
architecture, the load-bearing invariant (**no BouncyCastle type on the public surface**, enforced by
the guard test added in FEATURE-00E7), project layout, target frameworks & dependencies, build & test
commands, conventions, and the dev-workflow tracking summary.

Build & test commands to document:

```bash
dotnet build Enigma.DataEncryption.slnx -c Release
dotnet test --solution Enigma.DataEncryption.slnx -c Release
```

Note the `--solution` flag: on the .NET 10 SDK in MTP mode, `dotnet test <Solution>.slnx` is
rejected.

## Out of scope

- Any production type, interface, enum or exception (FEATURE-00E7).
- Any packaging metadata or release document (FEATURE-07DA).
- `docs/format.md` (FEATURE-00E7).
- `docs/guides/` (FEATURE-07DA PHASE02).
- Any CI workflow — **deliberately none**, consistent with `Enigma.Core` and the predecessor.
- Any UI or CLI project, now or ever.

## Acceptance criteria

1. `git init -b main` has been run; `git status` shows a repository with the working tree containing
   every artifact below and nothing else.
2. All 12 root artifacts exist as specified. `README.md` and `RELEASENOTES.md` are exactly 0 bytes.
3. `dotnet build Enigma.DataEncryption.slnx -c Release` succeeds with **zero warnings** across all
   three library TFMs and both test TFMs.
4. `dotnet test --solution Enigma.DataEncryption.slnx -c Release` runs the smoke test and passes on
   both `net8.0` and `net10.0`.
5. No csproj repeats `LangVersion`, `Nullable`, `ImplicitUsings` or `TreatWarningsAsErrors`.
6. No `PackageReference` carries a `Version=` attribute.
7. No `Microsoft.NET.Test.Sdk` or `xunit.runner.visualstudio` anywhere in the solution.
8. The library csproj carries **no** packaging metadata.
9. `docs/roadmap.md`, `docs/plan/` (6 files) and `docs/done/.gitkeep` are present.
10. `CLAUDE.md` describes the actual state of the repository at the end of this dev — no forward
    references written as if already true.

## Verification

```bash
dotnet build Enigma.DataEncryption.slnx -c Release
dotnet test --solution Enigma.DataEncryption.slnx -c Release
git status --porcelain     # inspect the untracked set is exactly what is intended
```

## Notes for the implementer

- `LangVersion 14` on `netstandard2.0` works for compiler-only features; PolySharp is what makes
  `init`/`required` members and nullable-analysis attributes (`[NotNullWhen]`, …) available there.
- Fill the `{{…}}` placeholders in every template; leaving one in place is a silent defect that
  survives to the published package.
- The `.gitattributes` `* text=auto eol=lf` rule is in place from the first commit, so there is no
  line-ending history to renormalize later. Take no `git add --renormalize` action.
