# Release runbook

Reusable checklist for publishing a new **Enigma.DataEncryption** version to NuGet. Only the packable
library project (`src/Enigma.DataEncryption`) is published; there is no Tools / CLI / Desktop project in
this solution, now or ever.

Replace `X.Y.Z` with the version being released (e.g. `1.0.0`) throughout. The version lives in
`src/Enigma.DataEncryption/Enigma.DataEncryption.csproj` (`<Version>`).

## 1. Pre-release checks

Run from the repository root, on the branch that will be merged:

- [ ] `<Version>X.Y.Z</Version>` set in `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj`.
- [ ] `RELEASENOTES.md` has a top `X.Y.Z` section describing the release (newest-first; any `(unreleased)`
      heading renamed to `X.Y.Z`).
- [ ] `<PackageReleaseNotes>` in the library csproj summarizes the release and points to `RELEASENOTES.md`.
      It duplicates the top of `RELEASENOTES.md` as prose — the two are kept in step by hand, so change
      them together.
- [ ] README badges and the "what's new" callout reflect `X.Y.Z`.
- [ ] `<TargetFrameworks>` reflect the `net8.0` + `net10.0` policy (`netstandard2.0` preserved to mirror
      Enigma.Core); any change was proposed/confirmed and logged in `RELEASENOTES.md` *Compatibility*.
- [ ] Clean, warning-free build across all TFMs (`TreatWarningsAsErrors` is on, so a warning is a failure):
      ```bash
      dotnet build Enigma.DataEncryption.slnx -c Release
      ```
- [ ] Full test suite green:
      ```bash
      dotnet test --solution Enigma.DataEncryption.slnx -c Release
      # Note the --solution flag: on the .NET 10 SDK in Microsoft.Testing.Platform mode,
      # `dotnet test Enigma.DataEncryption.slnx` is rejected.
      # If the test apphost can't find the runtime, prefix: DOTNET_ROOT=~/.dotnet
      ```
- [ ] README and guide samples verified against the built version. There is no doc-sample test project,
      so this is a manual cross-check against the real public surface of this library *and* Enigma.Core.

## 2. Merge to the default branch

Merge the release branch into `develop`, then `develop` into the default (published) branch — `main` —
via a pull request (or fast-forward), then check it out locally:

```bash
git switch main
git pull
```

## 3. Tag the release

Match the repo's existing tag convention — run `git tag` to see how prior releases were tagged (bare
`X.Y.Z` vs. `vX.Y.Z`). This family uses **bare `X.Y.Z`** (Enigma.Core `1.0.0`, the predecessor `1.2.0`),
which is also the default when a repo has no tags yet. Tag the merge commit and push the tag:

```bash
git tag X.Y.Z
git push origin X.Y.Z
```

## 4. Pack

`GeneratePackageOnBuild` is **off** for this library, so no `.nupkg` is produced on an ordinary build — pack
explicitly in Release to get the artifact you publish:

```bash
dotnet pack src/Enigma.DataEncryption/Enigma.DataEncryption.csproj -c Release -o ./artifacts
```

This writes `./artifacts/Enigma.DataEncryption.X.Y.Z.nupkg` — and nothing else; a `.snupkg` beside it means the
symbol opt-in crept back into the csproj. Confirm the version in the filename matches the tag, and
(optionally) inspect the package contents — it should bundle `README.md` and `LICENSE.md` and declare the
expected dependency floors:

| Target framework | Expected dependencies |
|---|---|
| `netstandard2.0` | `Enigma.Core`, `Microsoft.Extensions.DependencyInjection.Abstractions`, `System.Buffers` |
| `net8.0` | `Enigma.Core`, `Microsoft.Extensions.DependencyInjection.Abstractions` |
| `net10.0` | `Enigma.Core`, `Microsoft.Extensions.DependencyInjection.Abstractions` |

`PolySharp` must **not** appear — it is compile-only (`PrivateAssets="all"`). `System.Buffers` must appear
on `netstandard2.0` only; on `net8.0`+ it is framework-provided and referencing it would raise NU1510.

## 5. Push to NuGet

Publish with a NuGet API key that has push rights for the `Enigma.DataEncryption` package:

```bash
dotnet nuget push ./artifacts/Enigma.DataEncryption.X.Y.Z.nupkg \
  --api-key <NUGET_API_KEY> \
  --source https://api.nuget.org/v3/index.json
```

`dotnet pack` produces **only** the `.nupkg` — that single file is what gets pushed. This project does not
ship a `.snupkg` symbols package: the symbol opt-in properties (`IncludeSymbols`,
`SymbolPackageFormat`) are deliberately absent from the csproj and must stay that way, and `pack` is never
run with `--include-symbols`. The API key is a secret — never commit or echo it.

## 6. Post-publish verification

- [ ] The package page shows the new version: <https://www.nuget.org/packages/Enigma.DataEncryption> (indexing can
      take a few minutes).
- [ ] The README NuGet badge resolves to `X.Y.Z` (shields.io caches briefly).
- [ ] A scratch project can restore the new version:
      ```bash
      dotnet add package Enigma.DataEncryption --version X.Y.Z
      ```
- [ ] The GitHub release/tag is present and its notes match `RELEASENOTES.md`.
