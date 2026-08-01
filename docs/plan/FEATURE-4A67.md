# FEATURE-4A67 — Enigma.Core 1.1.0 upgrade & v1.1.0 release

**Status:** TODO (multi-phase)
**Type:** FEATURE (multi-phase, 2 phases)
**Branch (per phase, at build time):** `feature/feature-4a67-phaseNN-<slug>` — one branch per phase,
cut from the current `HEAD`.

## Why this exists

Enigma.Core released **1.1.0** on 2026-08-01 because BouncyCastle.Cryptography released **2.7.0**. It is a
pure dependency release — its own `docs/done/FEATURE-797D-PHASE01.md` records that no public API was added,
removed or changed, and that its two source edits were both forced by BouncyCastle deprecations under a
zero-warning gate. This library sits directly on Enigma.Core and inherits that floor transitively, so the
bump is a one-line Central Package Management edit here.

It is not, however, a no-op: **the upgrade changes one observable behaviour of this library** (see
*Planning-time evidence*), and that behaviour is documented on the public surface. Absorbing that change
deliberately — rather than discovering it from a bug report — is half of this item's work.

## Objective

Move the runtime dependency from **Enigma.Core 1.0.0 → 1.1.0** (raising the transitive
**BouncyCastle.Cryptography** floor from 2.6.2 to **≥ 2.7.0**), prove nothing else breaks, absorb and
document the one behaviour change, then cut and prepare the **v1.1.0** NuGet release.

No public API is added, removed or changed. The container format is untouched — format version stays
`0x10`, every header shape is unchanged, and every container written by 1.0.0 still decrypts.

## Context & constraints

- **Evolution of an existing, *published* codebase.** `Enigma.DataEncryption 1.0.0` went to nuget.org on
  **2026-07-31 20:21 UTC** and is tagged bare **`1.0.0`** at `a7eeec7` on `main`; `main` and `develop` are
  the same commit (`b1ab2c2`). This is a **routine release** in `dotnet-release` terms, not a first release
  — the 12 packaging properties are already in place and the third-party licence audit is not repeated.
- **`CLAUDE.md` and `docs/roadmap.md` are stale on that point** — both still say v1.0.0 is *"prepared but
  not published"* and that publishing "closes the format window" as a future event. It closed on
  2026-07-31. Correcting this is in scope (PHASE02, decision 4).
- **`FEATURE-F612` is in flight and is *not* a dependency of this item.** Its PHASE01 and PHASE02 are
  committed on the unmerged branches `feature/feature-f612-phase01-crypto` and
  `feature/feature-f612-phase02-format` (19 findings: 5 Medium, 14 Low, no Critical or High); the roadmap on
  `develop` still shows all five phases `TODO`. Its findings will mint a `CODE-REVIEW` item whose fixes ship
  in a **later** version — see decision 1.
- Central Package Management (`Directory.Packages.props`) — never a `Version=` attribute on a
  `PackageReference`.
- Shared build gates: `TreatWarningsAsErrors=true`, `EnforceCodeStyleInBuild=true`, `Nullable=enable`,
  `ImplicitUsings=disable`, `LangVersion=14`. **A warning is a build failure**, obsolescence warnings
  included.
- Library multi-targets `netstandard2.0;net8.0;net10.0`; tests target `net8.0;net10.0`. **No TFM change this
  release** — BouncyCastle 2.7.0 still ships `netstandard2.0`, so there is nothing to log in a
  *Compatibility* TFM note.
- Tests are MTP-native (`xunit.v3`, no `Microsoft.NET.Test.Sdk`); the suite is **28,272 tests** across the
  two test TFMs. Note the `--solution` flag: `dotnet test <Solution>.slnx` is rejected by the .NET 10 SDK in
  MTP mode.
- **Load-bearing invariant** — no `Org.BouncyCastle.*` type on the public surface
  (`tests/…/Api/BouncyCastleIsolationTests.cs`). This item makes no product-code change at all, so the
  invariant is untouched, but the guard must stay green.
- `.gitattributes` is present and every file this item touches is LF. Per `dev-workflow`, line endings are
  **recommendation-only** and are never fixed inside a dev.
- Published/default branch for the runbook: **`main`**. Tag convention: **bare `X.Y.Z`** (this repo's own
  `1.0.0`, Enigma.Core's `1.0.0`/`1.1.0`, the predecessor's `1.2.0`).

## Planning-time evidence (verified, **re-confirm at build time**)

The upgrade was executed during the interview against a throwaway `git archive develop` copy in the
scratchpad. **The repository itself was not modified.** Findings:

| Area | Result |
|---|---|
| Package availability | `Enigma.Core` **1.1.0** published 2026-08-01 18:38 UTC. Upstream: BouncyCastle 2.6.2 → 2.7.0; `coverlet.collector` 6.0.4 → 10.0.1 (test-only there). MIT throughout — redistribution unaffected. |
| Public API | **Unchanged.** Enigma.Core's own release notes and completion records state no public API was added, removed or changed; this library compiles against it with **zero source edits**. |
| Direct BouncyCastle coupling | **None.** No `Org.BouncyCastle.*` reference anywhere in `src/`; the library catches only `System.Security.Cryptography.CryptographicException`, `IOException`, `InvalidOperationException` and `UnauthorizedAccessException`. |
| Build | `dotnet build -c Release` → **clean, 0 warnings, all three TFMs**, after the one-line CPM edit and nothing else. |
| Full suite | **28,272 total — 28,264 passed, 8 failed** (4 distinct tests × 2 test TFMs). Everything else green: golden vectors, the ~4,700-case malformed-input sweep, thread-safety over six singletons, DI round-trips, both isolation guards, the fixture inventory. |
| Suite runtime | ~1 min 11 s for both TFMs — unchanged. |
| `dotnet list package --outdated` | Does **not** yet list Enigma.Core 1.1.0 (published the same day; search-index/HTTP-cache lag) although flat-container restore resolves it fine. If restore misses it at build time, clear `~/.nuget/http-cache` or restore with `--no-cache`. |

### The single break — an unparseable PEM changes exception type

BouncyCastle 2.7.0's `Org.BouncyCastle.Utilities.IO.Pem.PemReader.ReadPemObject()` now wraps a Base64
decode failure in `IOException("malformed PEM data: …")`. Enigma.Core's `PemUtils` already maps
`catch (IOException) → ArgumentException("The …-key PEM is malformed.", paramName)`, so the Base64 case has
moved into that bucket:

| | Enigma.Core 1.0.0 (BC 2.6.2) | Enigma.Core 1.1.0 (BC 2.7.0) |
|---|---|---|
| PEM whose Base64 is invalid | raw `FormatException`, unwrapped | `ArgumentException` (`ParamName` = `privateKeyPem` / `publicKeyPem`), with `IOException → FormatException` nested inside |

The four failing tests, all of which assert the old exact type:

| Test | File |
|---|---|
| `AnUnparseablePrivateKeyPemPropagatesUnwrapped` | `tests/…/Services/RsaFailureTests.cs` (~232) |
| `AnUnusablePublicKeyPemPropagatesUnwrapped` | `tests/…/Services/RsaFailureTests.cs` (~251) |
| `AnUnparseableRsaPrivateKeyPemPropagatesUnwrapped` | `tests/…/Services/HybridFailureTests.cs` (~350) |
| `AnUnusablePublicKeyIsReportedAgainstTheKeyThatCausedIt` | `tests/…/Services/HybridFailureTests.cs` (~378) |

**`docs/format.md` §9 is not violated.** Rows 582–583 promise that a malformed or unparseable PEM
"propagates from Enigma.Core (`ArgumentException` / `FormatException`) — **not** wrapped". Both types were
always permitted; only which branch fires has changed. The normative contract therefore needs no edit —
see decision 6.

## Design decisions (from the interview)

1. **Ship 1.1.0 now, independent of `FEATURE-F612`.** The bump is self-contained — no API change, no source
   edit, no format change — so entangling it with an unfinished audit would only delay a security-relevant
   dependency floor. F612's remaining phases continue on their own branches; the `CODE-REVIEW` item its
   report mints ships in a later version (1.1.1 or 1.2.0). **Consequence for ordering:** this item is
   appended last in the roadmap per the house append-last rule, but it is the **next item to build** — see
   the note added to `docs/roadmap.md`.
2. **Version = 1.1.0** (not a 1.0.1 patch). No public API moves, but raising the runtime dependency floor is
   consumer-visible — anyone pinned to BouncyCastle 2.6.x must upgrade — and there is a behaviour change on
   top. That is more than a patch implies, and it matches Enigma.Core's own precedent for the identical
   situation (`FEATURE-797D`).
3. **Bump Enigma.Core *and* the test-only tooling; hold `Microsoft.Extensions.DependencyInjection`.**
   `coverlet.collector` 6.0.4 → 10.0.1 and `Microsoft.Testing.Extensions.CodeCoverage` 18.0.4 → 18.9.0 are
   never redistributed, so the package's dependency floors do not move. `MEDI.Abstractions` (library) and
   `MEDI` (tests) stay at **9.0.18**: bumping them to 10.0.10 would raise a *second* consumer-visible floor
   in a release whose stated purpose is the BouncyCastle move, and the CPM comment requires the two to stay
   version-matched. The hold is logged in the release notes.
   *Note on `coverlet.collector`:* the CPM comment already concedes it "registers nothing with an MTP
   runner" — `Microsoft.Testing.Extensions.CodeCoverage` is what produces the figure. It is bumped anyway
   rather than dropped; **removing it is explicitly out of scope** for this item.
4. **Correct the stale published/format-window narrative** in `CLAUDE.md` and `docs/roadmap.md` (PHASE02).
   `CLAUDE.md` currently tells every future agent that the pre-publication window is open, which reads as
   *header changes are still free*. They are not: containers have existed outside this repository since
   2026-07-31, so a further header change now costs a format-version bump or a new method byte.
5. **Resolve the break by pinning the new behaviour exactly** — update the four tests to assert
   `ArgumentException` and its `ParamName`, keeping the Base64 case as its own assertion with a comment
   recording the drift and its cause. Rejected alternatives: (a) *tolerant assertions* (`ArgumentException`
   **or** `FormatException`) — survives future churn but stops detecting drift in a security-relevant path
   and loses the `ParamName` assertion; (b) *normalizing in the library* — would require sniffing the nested
   `FormatException` and rethrowing it, which is exactly the "do not re-split by exception shape or message
   text" pattern this repository forbids elsewhere, and would permanently couple the library to a
   BouncyCastle implementation detail. Pinning current behaviour is also what Enigma.Core did when it hit
   the same class of drift (its PEM characterization test, `FEATURE-797D` decision 5).
6. **Frame it as 1.1.0 with a *Compatibility* note; leave `docs/format.md` §9 as written.** §9 already
   permits both types, and keeping `FormatException` permitted stays honest if a future BouncyCastle version
   or another PEM path surfaces it again. Narrowing the spec to `ArgumentException` only was considered and
   rejected: it would mean changing a normative section in a dependency release, and re-widening later would
   itself be a documented change. **No *Breaking Changes & Migration* section** — the documented contract
   was never broken — but the behaviour change is spelled out explicitly under *Compatibility*.
7. **Re-measure coverage** after the collector bumps and update `CLAUDE.md`'s ~98% line / ~92% branch figures
   if they moved.
8. **Record the upstream gap as a cross-repo follow-up.** Enigma.Core 1.1.0's release notes state "the
   library's own behaviour is unchanged", which this probe disproves for the PEM path; its suite evidently
   has no characterization test for the invalid-Base64 case. This goes in
   `docs/done/FEATURE-4A67-PHASE01.md` under *Deviations & follow-ups*. **Fixing Enigma.Core is that
   repository's work item, not this one's.**
9. **Accept the `docs/roadmap.md` conflict with the F612 branches** and resolve it at merge time. New rows
   are appended last, so the overlap is confined to the ordering-notes prose that decision 4 already
   targets.
10. **Release stops at pack-verify.** The build makes the in-repo edits, packs once into a throwaway
    directory to inspect the real artifact, deletes it, and **prints** the tag / pack / push runbook.
    Tagging and publishing remain the maintainer's; the NuGet API key never appears in the repo or in any
    output.
11. **Historical `docs/plan/` and `docs/done/` records are not rewritten.** They are dated statements of
    what was true when that work shipped; the ones naming Enigma.Core 1.0.0 or BouncyCastle 2.6.2 stay as
    written. The same applies to the v1.0.0 section of `RELEASENOTES.md`.

## Definition of Done (applies to every phase)

Standard `dev-workflow` DoD:

1. `dotnet build Enigma.DataEncryption.slnx -c Release` succeeds with **zero warnings** across all three
   TFMs.
2. `dotnet test --solution Enigma.DataEncryption.slnx -c Release` passes in full on **net8.0 and net10.0**.
3. Every acceptance criterion of the phase is met.
4. The roadmap row and this plan file's phase status are updated.
5. `docs/done/FEATURE-4A67-PHASENN.md` is written.

---

## PHASE01 — Upgrade to Enigma.Core 1.1.0 & verify

**Status:** TODO
**Branch:** `feature/feature-4a67-phase01-enigma-core-110`

### Scope

**In scope**

| File | Change |
|---|---|
| `Directory.Packages.props` | `Enigma.Core` 1.0.0 → **1.1.0**; `coverlet.collector` 6.0.4 → **10.0.1**; `Microsoft.Testing.Extensions.CodeCoverage` 18.0.4 → **18.9.0** |
| `tests/…/Services/RsaFailureTests.cs` | 2 tests: `FormatException` assertion → `ArgumentException` + `ParamName` |
| `tests/…/Services/HybridFailureTests.cs` | 2 tests: same |
| `src/…/Services/IRsaDataEncryptionService.cs` | reword the `<exception>` clause that promises `FormatException` for invalid Base64 |
| `src/…/Services/RsaDataEncryptionService.cs` | same, on the internal `UnwrapDataKey` doc comment |
| `src/…/Services/HybridDataEncryptionService.cs` | same, on `UnwrapRsaSecret` |
| `docs/guides/rsa.md` | lines ~262 and ~304 — the two prose statements naming `FormatException` |
| `CLAUDE.md` | coverage figures, **only if** re-measurement shows they moved |

**Out of scope**

- **Any product-code change.** The doc-comment rewordings are the only edits under `src/`; no executable
  line changes. If a real source edit becomes necessary, **stop and reconcile the plan first**.
- `docs/format.md` §9 — already permits both exception types (decision 6).
- `Microsoft.Extensions.DependencyInjection` / `.Abstractions` — held at 9.0.18 (decision 3).
- Removing `coverlet.collector` (decision 3).
- Regenerating **any** of the 24 committed fixtures — they are the cross-version compatibility evidence and
  must pass **unmodified**.
- `xunit.v3` 3.2.2, `PolySharp` 1.16.0, `System.Buffers` 4.6.1 — already latest.
- The version bump and all release documentation — that is PHASE02.

### Design / approach

1. **Package versions.** Edit `Directory.Packages.props` only (CPM). Restore and confirm all three
   transitions resolve; if the restore cannot see Enigma.Core 1.1.0, clear `~/.nuget/http-cache` or restore
   with `--no-cache` (see *Planning-time evidence*). Confirm no `Version=` attribute has appeared on any
   `PackageReference` (grep every `.csproj`/`.props`).

2. **Build first, before touching a test.** The expected result is **0 warnings on all three TFMs with no
   source edit at all**. Anything else is new information and warrants stopping.

3. **The four tests — pin the new behaviour.** In each, the block currently reading

   ```csharp
   await Assert.ThrowsAsync<FormatException>(
       () => …(RsaTestData.MalformedPem, …));
   ```

   becomes an `ArgumentException` assertion checking `ParamName` — `privateKeyPem` on the decrypt side,
   `publicKeyPem` on the encrypt side (Enigma.Core's parameter names, not this library's). Keep it as a
   **separate assertion** rather than folding it into the adjacent loop, with a comment of roughly this
   shape:

   ```csharp
   // Base64 that is not Base64. Under Enigma.Core 1.0.0 (BouncyCastle 2.6.2) the platform decoder's
   // FormatException escaped raw; 2.7.0's PemReader wraps it in an IOException, which Enigma.Core maps
   // to ArgumentException. Both are §9 outcomes — this pins which one, so the next drift is a red test.
   // The FormatException is still there, nested two levels down.
   ```

   Update each test's `<summary>`/`<remarks>` where it describes the two outcomes. Where it is cheap, assert
   the nested `FormatException` is still reachable via `InnerException` — that is what makes the comment
   verifiable rather than folklore.

   `HybridFailureTests.AnUnparseableRsaPrivateKeyPemPropagatesUnwrapped` additionally asserts that an
   **empty** PEM is rejected by *this* library with `ParamName = "rsaPrivateKeyPem"`. That assertion is
   unaffected — do not disturb it; it is the distinction the test exists to draw.

4. **XML documentation.** Re-grep for the full set before editing (`grep -rn "FormatException" src/`); the
   known occurrences are `IRsaDataEncryptionService.cs:124`, `RsaDataEncryptionService.cs:283` and
   `HybridDataEncryptionService.cs:350`. Replace the "as `FormatException` where its Base64 is invalid"
   clause with wording along these lines: *a PEM that cannot be parsed is a credential-supply error and
   propagates from Enigma.Core unwrapped, as `ArgumentException`; `docs/format.md` §9 also permits
   `FormatException`, which Enigma.Core 1.1.0 no longer raises for this case but preserves as an inner
   exception.* Keep the §9 cross-reference in every clause that already carries one.

5. **Guide.** `docs/guides/rsa.md` lines ~262 and ~304 make the same promise in prose, and line 304 tells
   readers to add a second catch clause. Reword both to match the new reality, keeping §9's permissiveness
   visible. Because a guide is touched, the `dotnet-release` **snippet-verification gate fires**: cross-check
   every API reference in every code fence of `docs/guides/rsa.md` against the real public surface of this
   library *and* Enigma.Core, fix any mismatch in place, and record the coverage in the completion doc as a
   table (*snippets · symbols · mismatches · uncertain*, with totals).

6. **Coverage.** Re-measure after the collector bumps and compare against the recorded ~98% line / ~92%
   branch. Update `CLAUDE.md` only if the figures moved.

7. **Verification.** Full Release build across all three TFMs, then the whole suite on both test TFMs.
   Confirm specifically that the golden-vector suites, the malformed-input sweep, the thread-safety suite,
   the DI suite and both isolation guards pass with the fixtures untouched.

### Acceptance criteria

1. `Directory.Packages.props` pins `Enigma.Core` **1.1.0**, `coverlet.collector` **10.0.1** and
   `Microsoft.Testing.Extensions.CodeCoverage` **18.9.0**; `Microsoft.Extensions.DependencyInjection` and
   `.Abstractions` remain at **9.0.18**; no `Version=` attribute appears on any `PackageReference`.
2. `dotnet build Enigma.DataEncryption.slnx -c Release` succeeds with **0 warnings** on `netstandard2.0`,
   `net8.0` and `net10.0`.
3. The full suite passes on **net8.0 and net10.0** with **0 failures**. The total stays at **28,272** — the
   four tests are edited, not added.
4. **All 24 committed fixtures are byte-identical**: `git status --porcelain` over
   `tests/Enigma.DataEncryption.UnitTests/Services/Fixtures` prints nothing. This is the cross-version
   evidence that every 1.0.0-era container still decrypts unchanged under BouncyCastle 2.7.0, and it must be
   stated as such in the completion doc.
5. The four PEM tests pin `ArgumentException` with the correct `ParamName`, each carrying a comment naming
   Enigma.Core 1.1.0 / BouncyCastle 2.7.0 as the cause of the change.
6. No `<exception>` clause or prose statement anywhere in `src/` or `docs/guides/` still promises
   `FormatException` as the outcome for an invalid-Base64 PEM; `docs/format.md` §9 is **unmodified**.
7. `Api/BouncyCastleIsolationTests` and `Api/InternalSurfaceIsolationTests` are green — no BouncyCastle type
   and no `Internal/` type reaches the public surface.
8. The malformed-input sweep (~4,700 cases per TFM), the thread-safety suite (six singletons) and the DI
   suite are green.
9. Coverage re-measured; `CLAUDE.md`'s figures updated if they moved, or the completion doc states they did
   not.
10. The snippet-verification coverage table for `docs/guides/rsa.md` is recorded in the completion doc.
11. `docs/done/FEATURE-4A67-PHASE01.md` records: all three dependency transitions and the held-back set; the
    before/after exception shape with its BouncyCastle root cause; the cross-version fixture evidence; the
    build and test counts; and the **cross-repo follow-up** of decision 8.

---

## PHASE02 — Release v1.1.0

**Status:** TODO
**Branch:** `feature/feature-4a67-phase02-release-110`

Follows `dotnet-release`'s **routine release** path (a published version already exists): version, notes,
callout, dependency log, pack-verify, runbook.

### Scope

**In scope**

| File | Change |
|---|---|
| `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj` | `<Version>` 1.0.0 → **1.1.0**; rewrite `<PackageReleaseNotes>` |
| `RELEASENOTES.md` | **prepend** a v1.1.0 section |
| `README.md` | what's-new callout `1.0` → `1.1`; line ~64 `built on Enigma.Core 1.0.0` → `1.1.0` |
| `SECURITY.md` | supported-versions table `1.0.x` → `1.1.x` |
| `CLAUDE.md` | runtime dependency `Enigma.Core 1.0.0` → `1.1.0` (line ~234); the stale-narrative correction (lines ~302–316); a note on the new PEM exception behaviour |
| `docs/roadmap.md` | the same narrative correction (lines ~61–67) |
| `docs/RELEASE.md` | verify only — see design step 7 |

**Out of scope**

- The v1.0.0 section of `RELEASENOTES.md` and every historical `docs/plan/` / `docs/done/` record
  (decision 11).
- `README.md` badges — the NuGet-version badge self-tracks and there is no Downloads badge (house set) —
  and the supported-TFM line, since the TFM set did not move.
- The six guides other than `docs/guides/rsa.md`; none names a package version, and `rsa.md` was already
  handled in PHASE01, so **the snippet gate does not fire again in this phase**.
- `CHANGELOG.md` — `RELEASENOTES.md` is the single release-notes source; do not add one.
- Any `src/` change, any tag, any publish.

### Design / approach

1. **csproj.** `<Version>1.1.0</Version>`. Replace `<PackageReleaseNotes>` with a short prose summary
   mirroring the top of the new `RELEASENOTES.md` section, ending
   `See RELEASENOTES.md for the full details.` — the two are duplicated prose kept in step by hand, so
   change them together. Confirm in passing that all 12 packable-library properties are still present,
   `GeneratePackageOnBuild` is still absent, and no symbol property (`IncludeSymbols`,
   `SymbolPackageFormat`, `PublishRepositoryUrl`, `EmbedUntrackedSources`) has crept in.

2. **`RELEASENOTES.md`.** Prepend a `# Enigma.DataEncryption v1.1.0 Release Notes` section above the 1.0.0
   one, using the subsequent-release variant and only the non-empty sub-sections, in order:

   - **Dependencies** — `Enigma.Core 1.0.0 → 1.1.0`, which raises **BouncyCastle.Cryptography 2.6.2 →
     2.7.0** transitively; `coverlet.collector 6.0.4 → 10.0.1` and
     `Microsoft.Testing.Extensions.CodeCoverage 18.0.4 → 18.9.0` (test-only, not redistributed);
     `Microsoft.Extensions.DependencyInjection.Abstractions` **held at 9.0.18** deliberately.
   - **Compatibility** — no public API added, removed or changed; target frameworks unchanged
     (`netstandard2.0`, `net8.0`, `net10.0`); the **minimum BouncyCastle.Cryptography is now 2.7.0**, so
     consumers pinned to 2.6.x must upgrade; the **container format is unchanged** (version `0x10`, every
     header shape identical), so every container written by 1.0.0 decrypts unchanged — verified against the
     24 committed 1.0.0-era fixtures; and the **behaviour change**: a PEM whose Base64 is invalid now throws
     `ArgumentException` (naming the offending parameter) where 1.0.0 threw `FormatException`, with the
     `FormatException` preserved as a nested inner exception. State plainly that `docs/format.md` §9 always
     permitted both types, so the documented contract is unchanged — only which branch fires.

   No *New Features*, *Fixes* or *Breaking Changes & Migration* sub-section (decision 6).

3. **`README.md`.** What's-new callout to `1.1` with a one-line highlight; the *Installation* line
   `built on Enigma.Core 1.0.0` → `1.1.0`.

4. **`SECURITY.md`.** Supported-versions table `1.0.x` → `1.1.x` (latest released version only, per the
   existing policy text).

5. **`CLAUDE.md`.** Three edits:
   - the runtime-dependency line → `Enigma.Core 1.1.0`;
   - **the narrative correction** — replace "v1.0.0 is prepared but *not published*…" and the
     pre-publication-window paragraph with the facts: v1.0.0 **was published on 2026-07-31** and is tagged
     `1.0.0`; the format window is **closed**, so a further header change now costs a format-version bump or
     a new method byte; `FEATURE-F612` is a **post-release** audit whose report mints a `CODE-REVIEW` item
     that ships in a later 1.x, not a gate on a first publication. Keep the code-freeze statement about
     F612 — it is still true.
   - a short note recording that Enigma.Core 1.1.0 changed the unparseable-PEM exception type, so a future
     agent reading §9 knows which branch actually fires.

6. **`docs/roadmap.md`.** Apply the same correction to the ordering-notes paragraph that says v1.0.0 "is
   prepared but not published" and that "publishing closes the window". Expect a merge conflict with the
   F612 branches here and resolve it at merge time (decision 9).

7. **`docs/RELEASE.md`.** Checked at planning time: its dependency-floor table lists **package names only,
   with no versions**, so there is nothing to refresh there — this corrects the interview summary, which
   assumed a version-bearing line. The one candidate edit is the tag-convention sentence (line ~50), which
   cites Enigma.Core and the predecessor as the precedent for bare `X.Y.Z`; this repository now has its own
   `1.0.0` tag and can cite itself. **Optional and cosmetic — make it or skip it, but say which in the
   completion doc.**

8. **Pack-verify** (local, then deleted):

   ```bash
   dotnet pack src/Enigma.DataEncryption/Enigma.DataEncryption.csproj -c Release -o ./artifacts-verify
   ```

   Confirm from the `.nupkg` and its nuspec: version **1.1.0**; the directory holds the `.nupkg` **and
   nothing else** (no `.snupkg`); `README.md` embedded and **non-empty**, and it is the *updated* README;
   `LICENSE.md` embedded; nuspec `<version>`, `<title>`, `<license type="file">`, `<readme>` and
   `<releaseNotes>` all correct; `lib/{netstandard2.0,net8.0,net10.0}/Enigma.DataEncryption.dll` + `.xml`
   present on all three TFMs; and the per-TFM dependency floors:

   | Target framework | Expected dependencies |
   |---|---|
   | `net8.0` | `Enigma.Core >= 1.1.0`, `Microsoft.Extensions.DependencyInjection.Abstractions >= 9.0.18` |
   | `net10.0` | `Enigma.Core >= 1.1.0`, `Microsoft.Extensions.DependencyInjection.Abstractions >= 9.0.18` |
   | `.NETStandard2.0` | the same two, plus `System.Buffers >= 4.6.1` |

   `PolySharp` must **not** appear in any dependency group (compile-only, `PrivateAssets=all`). Then
   **delete the verify directory** — it is a scratch artifact and is never committed.

9. **Print the runbook** — pre-flight, merge to `main`, bare **`1.1.0`** tag, publish `dotnet pack` into
   `./artifacts`, `dotnet nuget push`, then post-publish verification. **Printed, never run** (decision 10).

### Acceptance criteria

1. `<Version>1.1.0</Version>` and a `<PackageReleaseNotes>` mirroring the new notes section and ending
   `See RELEASENOTES.md for the full details.`
2. `RELEASENOTES.md` has a top v1.1.0 section with *Dependencies* and *Compatibility* only, recording all
   three transitions **and** the held-back `MEDI.Abstractions`, the raised BouncyCastle floor, the unchanged
   container format, and the PEM exception-type change. The 1.0.0 section below is preserved unmodified.
3. `README.md`, `SECURITY.md` and `CLAUDE.md` are consistent at **1.1.0 / Enigma.Core 1.1.0**; badges and
   the TFM list unchanged.
4. `CLAUDE.md` and `docs/roadmap.md` no longer claim v1.0.0 is unpublished or that the format window is
   open, and both state the publication date and the consequence for future header changes.
5. Release build clean with **0 warnings** on all three TFMs; the full suite green on both test TFMs —
   **re-verified in this phase**, not carried over from PHASE01.
6. Pack-verify passed on **every** point of design step 8, and the verify directory was deleted.
7. The tag / pack / push runbook is **printed, not run**, using the bare `1.1.0` tag format; the NuGet API
   key appears nowhere.
8. `docs/done/FEATURE-4A67-PHASE02.md` written, stating whether the optional `docs/RELEASE.md` edit was made.
9. The item's roadmap row flips to `DONE` alongside PHASE02, this plan file's statuses with it.

---

## Out of scope / recorded for later

- **Enigma.Core's own release-notes gap** (decision 8) — a `BUG`/`FEATURE` item in that repository to amend
  the 1.1.0 *Compatibility* section and add a characterization test for the invalid-Base64 PEM case. Cannot
  be allocated from here.
- **`FEATURE-F612` PHASE03–PHASE05** and the `CODE-REVIEW` item its report mints — unchanged by this item,
  and its fixes ship in a later 1.x (decision 1).
- **Dropping `coverlet.collector`** and **bumping `MEDI` to 10.0.10** — both deliberately deferred
  (decision 3); the next release has to decide about them again.
- **Wiring coverage differently** or changing the test runner — untouched.

## If this is dropped

Mark the row `ABANDONED` with a reason rather than deleting it, and mirror the note at the top of this file.
The consequence of dropping it: the library stays on Enigma.Core 1.0.0 / BouncyCastle 2.6.2 indefinitely,
and the exception-type divergence between this library's documentation and Enigma.Core's current behaviour
becomes a latent surprise for the first consumer who upgrades Enigma.Core independently — which NuGet will
let them do, since the published 1.0.0 floor is `Enigma.Core >= 1.0.0`.
