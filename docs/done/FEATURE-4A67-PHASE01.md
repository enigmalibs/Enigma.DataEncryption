# FEATURE-4A67-PHASE01 — Upgrade to Enigma.Core 1.1.0 & verify

**Status:** DONE
**Branch:** `feature/feature-4a67-phase01-enigma-core-110`
**Plan:** `docs/plan/FEATURE-4A67.md` (PHASE01)

## Summary

Moved the runtime dependency from **Enigma.Core 1.0.0 → 1.1.0**, raising the transitive
**BouncyCastle.Cryptography** floor from 2.6.2 to **2.7.0**. No product code changed: the library compiles
against the new Enigma.Core with **zero source edits**, and the only edits under `src/` are three XML doc
comments. The container format is untouched, and all 24 committed 1.0.0-era fixtures decrypt unmodified.

The upgrade's one observable behaviour change was absorbed deliberately rather than left to a bug report: a
PEM whose Base64 is invalid now surfaces as `ArgumentException` instead of a bare `FormatException`. Four
tests were re-pointed to pin the new shape, and every doc comment and guide sentence that promised the old
one was reworded.

One planned dependency bump could not be taken as specified — `Microsoft.Testing.Extensions.CodeCoverage`
18.9.0 is incompatible with `xunit.v3` 3.2.2. It was pinned to **18.0.6** instead, with the maintainer's
agreement; see *Deviations & follow-ups*.

## Dependency transitions

| Package | From | To | Notes |
|---|---|---|---|
| `Enigma.Core` | 1.0.0 | **1.1.0** | The point of the release. Redistributed — moves the package's floor. |
| `BouncyCastle.Cryptography` | 2.6.2 | **2.7.0** | Transitive, via Enigma.Core. Verified resolved on all three TFMs. |
| `coverlet.collector` | 6.0.4 | **10.0.1** | Test-only, never redistributed. Standalone — the package declares **no** dependencies, so it cannot perturb the MTP graph. |
| `Microsoft.Testing.Extensions.CodeCoverage` | 18.0.4 | **18.0.6** | Test-only. **Amended from the planned 18.9.0** — see below. |

**Held back deliberately** (decision 3): `Microsoft.Extensions.DependencyInjection.Abstractions` (library)
and `Microsoft.Extensions.DependencyInjection` (tests) both stay at **9.0.18** — bumping them would raise a
second consumer-visible floor in a release whose stated purpose is the BouncyCastle move, and the CPM
comment requires the two to stay version-matched. `xunit.v3` 3.2.2, `PolySharp` 1.16.0 and `System.Buffers`
4.6.1 are already the latest stable and were not touched.

No `Version=` attribute appears on any `PackageReference` anywhere in the repository — CPM remains the only
version source.

## The behaviour change — an unparseable PEM changes exception type

BouncyCastle 2.7.0's `Org.BouncyCastle.Utilities.IO.Pem.PemReader.ReadPemObject()` now wraps a Base64
decode failure in an `IOException`. Enigma.Core's `PemUtils` already maps `catch (IOException) →
ArgumentException(…, paramName)`, so the invalid-Base64 case moved into that bucket:

| | Enigma.Core 1.0.0 (BC 2.6.2) | Enigma.Core 1.1.0 (BC 2.7.0) |
|---|---|---|
| PEM whose Base64 is invalid | raw `FormatException`, unwrapped | `ArgumentException` (`ParamName` = `privateKeyPem` / `publicKeyPem`) |

The exact chain, confirmed by assertion rather than by reading the stack trace, is
`ArgumentException → IOException → FormatException`. The original `FormatException` is therefore still
reachable; it is no longer the exception the caller catches.

**`docs/format.md` §9 is not violated and was not modified.** Rows 582–583 always permitted both
`ArgumentException` and `FormatException` for an unparseable PEM; only which branch fires has changed. The
normative contract is intact, which is why this is a minor-version behaviour note and not a breaking change
(decision 6).

### How it was resolved

Per decision 5, the new behaviour is **pinned exactly** rather than absorbed by a tolerant assertion or
normalized inside the library. The four tests below now assert `ArgumentException`, check `ParamName`
(Enigma.Core's name, not this library's), and assert the nested `FormatException` is still reachable — which
is what makes the explanatory comment verifiable instead of folklore. Each carries a comment naming
Enigma.Core 1.1.0 / BouncyCastle 2.7.0 as the cause.

| Test | File |
|---|---|
| `AnUnparseablePrivateKeyPemPropagatesUnwrapped` | `tests/…/Services/RsaFailureTests.cs` |
| `AnUnusablePublicKeyPemPropagatesUnwrapped` | `tests/…/Services/RsaFailureTests.cs` |
| `AnUnparseableRsaPrivateKeyPemPropagatesUnwrapped` | `tests/…/Services/HybridFailureTests.cs` |
| `AnUnusablePublicKeyIsReportedAgainstTheKeyThatCausedIt` | `tests/…/Services/HybridFailureTests.cs` |

The nested-exception check is a small shared helper, `RsaTestData.FirstFormatException`, which **walks** the
`InnerException` chain rather than indexing a fixed depth — the depth is BouncyCastle's, not ours, and a
future version could add or drop a layer without changing the outcome the format spec cares about.

`HybridFailureTests.AnUnparseableRsaPrivateKeyPemPropagatesUnwrapped`'s separate assertion that an **empty**
PEM is rejected by *this* library with `ParamName = "rsaPrivateKeyPem"` was left untouched, as the plan
required — it is the distinction that test exists to draw.

## Cross-version compatibility evidence

**All 24 committed fixtures pass byte-identical** — `git status --porcelain` over
`tests/Enigma.DataEncryption.UnitTests/Services/Fixtures` prints nothing. Not one was regenerated. Those
fixtures were produced under Enigma.Core 1.0.0 / BouncyCastle 2.6.2, so their passing **is** the evidence
that every container written by the published v1.0.0 still decrypts unchanged under BouncyCastle 2.7.0:
same format version `0x10`, same header shapes, same golden bytes, same key-confirmation tags.

## Files touched

**Modified**

| File | Change |
|---|---|
| `Directory.Packages.props` | Three version bumps; a new comment recording the MTP v1/v2 constraint that caps the coverage collector |
| `src/…/Services/IRsaDataEncryptionService.cs` | `<exception>` clause reworded (no longer promises `FormatException` for invalid Base64) |
| `src/…/Services/RsaDataEncryptionService.cs` | `UnwrapDataKey` remarks reworded, §9 cross-reference kept |
| `src/…/Services/HybridDataEncryptionService.cs` | `UnwrapRsaSecret` remarks reworded, §9 cross-reference kept |
| `tests/…/Services/RsaFailureTests.cs` | 2 tests re-pointed to `ArgumentException` + `ParamName` + nested `FormatException` |
| `tests/…/Services/HybridFailureTests.cs` | 2 tests, same |
| `tests/…/Services/RsaTestData.cs` | New `FirstFormatException` helper |
| `docs/guides/rsa.md` | 2 prose statements reworded; **2 snippets fixed** (missing `using`) |
| `docs/guides/hybrid.md` | 1 prose statement reworded (out-of-plan; see below) |
| `CLAUDE.md` | Doc-freshness sweep: the MTP v1 / coverage-collector constraint added to *Build & test*. **Not** the coverage figures (unmoved) and **not** the `Enigma.Core 1.0.0` line at 234, which is PHASE02's |
| `docs/roadmap.md`, `docs/plan/FEATURE-4A67.md` | Statuses; acceptance criterion 1 amended |

**Created:** this file. **Deleted:** nothing. **No executable line under `src/` changed.**

## Snippet-verification coverage

The gate fired because guides were touched. Rather than eyeballing symbols, every C# fence was extracted and
**compiled against the real assemblies** — a project reference to this library plus `Enigma.Core` 1.1.0 — so
"verified" means the compiler agreed. The two fences that are interface *signature listings* rather than
runnable code were instead diffed against the interface declarations in source.

| Guide | Fences | Verified how | Symbols (this library / Enigma.Core) | Mismatches | Uncertain |
|---|---|---|---|---|---|
| `docs/guides/rsa.md` | 9 (8 C# + 1 signature listing) | 8 compiled; listing diffed against `IRsaDataEncryptionService` | 12 / 3 | **2 — both fixed** | 0 |
| `docs/guides/hybrid.md` | 8 (6 C# + 1 signature listing + 1 `text`) | 6 compiled; listing diffed against `IHybridDataEncryptionService` | 14 / 5 | 0 | 0 |
| **Total** | **17** | — | — | **2** | **0** |

Both signature listings match their interfaces exactly — parameter names, types, order, defaults, including
`RsaOaepHash oaepHash = RsaOaepHash.Sha256` and `MLKemParameterSet parameterSet =
MLKemParameterSet.MLKem1024`.

**The two mismatches were pre-existing and unrelated to this upgrade.** Both are in `rsa.md`: the fences
demonstrating the RSA-1024/SHA-512 key-size failure and the progress/cancellation flow use `RsaOaepHash`
without `using Enigma.Core.Asymmetric.PublicKey;`. `RsaOaepHash` is an **Enigma.Core** type this library
re-exposes, so `using Enigma.DataEncryption;` alone does not bring it into scope — a reader copying the
second fence verbatim (it is otherwise complete and standalone) gets `CS0103`. The other three `rsa.md`
fences that use the type already had the directive; these two had been missed. Both fixed.

Three fences (`rsa.md` catch-ordering, `hybrid.md` limits and progress) deliberately leave credential
variables bound by surrounding prose. They were compiled with stub bindings so their **API** references were
still checked; the unbound identifiers are an authoring choice, not a defect. Worth noting for a future
guides pass: the `rsa.md` equivalents of the latter two *do* declare their variables, so the two guides are
mildly inconsistent about it. Not changed here — out of scope, and it is a style question rather than a
correctness one.

## Coverage

Re-measured after the collector bumps, `--coverage --coverage-output-format cobertura`, `Enigma.DataEncryption`
package only:

| TFM | Line | Branch |
|---|---|---|
| net8.0 | **98.02%** | **92.09%** |
| net10.0 | **98.02%** | **92.09%** |

Identical to the figures `docs/done/FEATURE-0D64.md` recorded, and consistent with `CLAUDE.md`'s ~98% line /
~92% branch. **The figures did not move, so `CLAUDE.md` was not edited** (acceptance criterion 9's second
branch).

## Build/test evidence

- `dotnet build Enigma.DataEncryption.slnx -c Release --no-incremental` → **Build succeeded, 0 Warning(s),
  0 Error(s)** across `netstandard2.0`, `net8.0` and `net10.0`.
- `dotnet test --solution Enigma.DataEncryption.slnx -c Release` → **total 28,272 · failed 0 · succeeded
  28,272 · skipped 0**, both test TFMs. The total is **unchanged** from 1.0.0 — the four tests were edited,
  not added.
- Suite runtime ~1 min 13 s for both TFMs — unchanged.
- Intermediate evidence, before the test edits: the same suite ran **28,264 passed / 8 failed** — exactly
  the 4 tests × 2 TFMs the plan predicted, no more, with the failure stack showing
  `PemReader.ReadPemObject` → `Convert.FromBase64CharPtr`. Nothing else in the suite reacted to the upgrade.

Named suites, run individually for the record (counts across both TFMs):

| Suite | Tests | Result |
|---|---|---|
| `MalformedContainerSweepTests` (~4,724 cases per TFM) | 9,448 | pass |
| `ServiceThreadSafetyTests` (six singletons) | 34 | pass |
| `GoldenVectorInventoryTests` (fixture inventory) | 112 | pass |
| `Api` namespace — `BouncyCastleIsolationTests`, `InternalSurfaceIsolationTests`, `FormatConstantsTests` | 44 | pass |
| `DependencyInjection` namespace | 50 | pass |

Both load-bearing isolation guards are green: no `Org.BouncyCastle.*` type and no `Internal/` type reaches
the public surface. That guard mattered more than usual this time — the upgrade moved BouncyCastle itself.

## Deviations & follow-ups

1. **`Microsoft.Testing.Extensions.CodeCoverage` pinned to 18.0.6, not the planned 18.9.0.** Raised with the
   maintainer mid-build and agreed. 18.9.0 depends on `Microsoft.Testing.Platform` ≥ **2.3.0**, while
   `xunit.v3` 3.2.2 is an MTP **v1** host — it ships `xunit.v3.core.mtp-v1` / `xunit.v3.mtp-v1` and pulls
   `Microsoft.Testing.Platform.MSBuild` **1.9.1**. The pairing **builds with zero warnings** and then dies at
   test-host startup:

   ```
   Unhandled exception. System.TypeLoadException: Could not load type
   'Microsoft.Testing.Platform.Extensions.TestHost.IDataConsumer' from assembly
   'Microsoft.Testing.Platform, Version=2.3.0.0, …'
   ```

   Zero tests ran, both TFMs, exit code 134. The failure mode is worth remembering: a silent build and an
   empty test run, which a less careful pass could mistake for success. The **entire 18.1.0+ line** requires
   MTP 2.x (18.1.0 → 2.0.0, 18.5.1 → 2.1.0, 18.7.0 → 2.2.1, 18.9.0 → 2.3.0); **18.0.6** is the highest
   release still on MTP 1.8.4, and it was verified green. The constraint is now recorded as a comment in
   `Directory.Packages.props` so the next agent does not rediscover it, and acceptance criterion 1 in the
   plan was amended with the evidence.

   **Follow-up:** reaching CodeCoverage 18.x-current requires `xunit.v3` **4.x**, which is prerelease only
   (`4.0.0-pre.154` as of 2026-08-01). Revisit when 4.x is stable — the two must move together.

   The planning-time probe reported the suite running with 8 failures, which cannot have been true with
   18.9.0 pinned; its restore evidently did not resolve that version.

2. **Cross-repo follow-up — Enigma.Core's release notes are wrong on this point** (decision 8). Enigma.Core
   1.1.0's notes state "the library's own behaviour is unchanged". This upgrade disproves that for the PEM
   path: the exception type a caller catches for an invalid-Base64 PEM changed from `FormatException` to
   `ArgumentException`. Enigma.Core's suite evidently has no characterization test for that case, or it would
   have caught it — this repository's did. Suggested there: amend the 1.1.0 *Compatibility* section and add
   the missing test. **Fixing Enigma.Core is that repository's work item; it cannot be allocated from here.**

3. **`docs/guides/hybrid.md` was edited although the plan's scope table named only `rsa.md`.** Confirmed with
   the maintainer before proceeding. Its line 270 also named `FormatException` as an outcome for an unusable
   RSA public-key PEM. Strictly, acceptance criterion 6 was satisfiable without touching it — the sentence
   lists both §9-permitted types rather than promising `FormatException` for the Base64 case specifically —
   but leaving it would have pointed readers at a branch Enigma.Core 1.1.0 no longer takes. Touching it fired
   the snippet gate for that guide too, which is why the table above covers both.

4. **No `docs/format.md` change**, as decision 6 requires. §9 already permits both exception types, and
   keeping `FormatException` permitted stays honest if a future BouncyCastle version surfaces it again.

5. **No product-code change.** The plan's out-of-scope rule — stop and reconcile if a real source edit
   becomes necessary — was never triggered. The three `src/` edits are XML doc comments; no executable line
   moved.

6. **Documentation freshness sweep.** The version staleness this dev created — `CLAUDE.md:234` and
   `README.md:64`, both naming Enigma.Core 1.0.0 — is already in PHASE02's scope table, so it was left for
   the next dev rather than edited twice. One item was **not** covered by PHASE02 and was folded into this
   commit: the MTP v1 constraint from deviation 1, added to `CLAUDE.md`'s *Build & test* section. It
   previously existed only as a `Directory.Packages.props` comment, and its failure mode (clean build, zero
   tests) is one an agent reading only `CLAUDE.md` should not have to rediscover.

7. **Line endings:** no CRLF/LF noise observed. Every file touched is LF and `.gitattributes` is in place.
   No action taken (recommendation-only per `dev-workflow`).

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | CPM pins verified; MEDI held at 9.0.18; no `Version=` attribute | **Met, as amended** (18.0.6, not 18.9.0 — see deviation 1) |
| 2 | Release build, 0 warnings, all three TFMs | Met |
| 3 | Full suite green both TFMs; total stays 28,272 | Met |
| 4 | All 24 fixtures byte-identical | Met |
| 5 | Four PEM tests pin `ArgumentException` + `ParamName`, each with a cause comment | Met |
| 6 | No `FormatException` promise left in `src/` or `docs/guides/`; `docs/format.md` unmodified | Met |
| 7 | Both isolation guards green | Met |
| 8 | Malformed sweep, thread-safety and DI suites green | Met |
| 9 | Coverage re-measured; figures unmoved, so `CLAUDE.md` untouched | Met |
| 10 | Snippet-verification coverage table recorded | Met (both guides) |
| 11 | This document records the transitions, the exception shape, the fixture evidence, the counts and the cross-repo follow-up | Met |
