# FEATURE-07DA-PHASE03 — README + release notes + community files — DONE

**Branch:** `feature/feature-07da-phase03-readme`
**Plan:** `docs/plan/FEATURE-07DA.md` § PHASE03

## Summary

The two release documents this repo has carried as **0-byte placeholders since bootstrap** are now written,
plus the one community file the plan told me to offer.

`README.md` is the packed, nuget.org-facing landing page, written from the `dotnet-release`
`package-README.md` template in the mandated section order — title → badges → one-paragraph intro →
what's-new callout → *Features* → *Installation* → *Quick start* → *Documentation* → *License*, with one
optional `###` subsection ("Asynchronous, cancellable, observable") for the property that spans every
category rather than belonging to any one of them. Exactly the two house badges, in order, and **no
Downloads badge** — on a package with no downloads yet it advertises the wrong number. Length is kept to
summary depth: the *Features* bullets name capabilities, and the guides carry the detail.

`RELEASENOTES.md` uses the template's **first-release** variant (*Feature overview · Compatibility ·
Version*), with the feature overview at slightly more depth than the README's bullets. The
predecessor-incompatibility statement the plan requires is its own `###` subsection rather than a single
line, because there are four independent format changes to name and one mechanism (the reserved
`0x01`–`0x0F` version range) that explains how a future release could still read old files.

`PackageReleaseNotes` — provisional since PHASE01, by that phase's own note — was rewritten to mirror the
finished `RELEASENOTES.md` top, still ending with the required `See RELEASENOTES.md for the full details.`
A comment now sits above it saying the two must be kept in step, so the next release does not update one
and forget the other.

`SECURITY.md` was **offered and accepted**, from the template. Its "why correctness matters" paragraph and
its *Scope* section are written for this library specifically: the in-scope examples are the failure modes
a cryptographic container actually has (a header field escaping validation, decryption accepting a
container it should reject, key material not cleared, a divergence from `docs/format.md`), and the upstream
pointer names the real two-layer chain — Enigma.Core for the primitives, BouncyCastle beneath it. Per the
template it carries **no email address**: reporting goes through GitHub private vulnerability reporting.

The plan's *snippet-verification gate* applied to the README's one quick-start snippet, and I took it
further than the manual cross-check PHASE02 used — see below.

## Files touched

**Created**

| Path | What |
|---|---|
| `SECURITY.md` | Security policy: supported versions (1.0.x), GitHub private vulnerability reporting, what to expect, scope + upstream pointers. |
| `docs/done/FEATURE-07DA-PHASE03.md` | This record. |

**Modified**

| Path | What |
|---|---|
| `README.md` | Written from 0 bytes — the packed nuget.org landing page. |
| `RELEASENOTES.md` | Written from 0 bytes — first-release notes. |
| `src/Enigma.DataEncryption/Enigma.DataEncryption.csproj` | `PackageReleaseNotes` rewritten to mirror `RELEASENOTES.md`, plus a keep-in-step comment. Metadata property 11 only — no other property touched. |
| `docs/roadmap.md` | PHASE03 → `IN PROGRESS`, then → `DONE`. |
| `docs/plan/FEATURE-07DA.md` | PHASE03 status → `DONE` with a pointer to this record. |

**Deleted:** none.

## The snippet-verification gate

The README has one code fence — the quick start. There is no permanent doc-sample test project (PHASE02
recorded that as a considered-and-declined alternative), so the gate is a per-dev obligation. Rather than
cross-check the snippet by eye as PHASE02 did, I **extracted it verbatim from `README.md` and compiled and
ran it**, which is strictly stronger evidence:

```bash
# awk-extracted the ```csharp fence from README.md into Program.cs of a throwaway
# net10.0 console project in the scratchpad, ProjectReference'd at the real library,
# with TreatWarningsAsErrors=true / Nullable=enable / ImplicitUsings=disable to match house settings.
dotnet build ...  ->  Build succeeded. 0 Warning(s) 0 Error(s)
dotnet ...dll     ->  Attack at dawn.
```

Three things this proved that reading cannot: the snippet **compiles** against the shipped surface; it
compiles with **zero warnings** under `TreatWarningsAsErrors` and `ImplicitUsings=disable`, so its `using`
block is exactly right with nothing unused; and it **prints precisely what its trailing comment claims**
(`// Attack at dawn.`). The throwaway project lived in the session scratchpad, never in the repo, and was
deleted afterwards.

### Coverage

| File | Snippets | Library symbols | Enigma.Core symbols | Mismatches | Uncertain |
|---|---|---|---|---|---|
| `README.md` — quick start (compiled + run) | 1 | 7 | 0 | 0 | 0 |
| `README.md` — prose symbol references | — | 11 | 0 | 0 | 0 |
| `RELEASENOTES.md` — prose symbol references | — | 13 | 0 | 0 | 0 |
| **Total** | **1** | **31** | **0** | **0** | **0** |

The quick start deliberately uses no Enigma.Core symbol — key generation is what forces Enigma.Core onto
the page, and the README's one snippet is the password idiom, which needs none. The RSA and ML-KEM guides
already carry that surface and PHASE02 verified it.

Library symbols verified in the snippet: `IArgon2DataEncryptionService`, `Argon2DataEncryptionService`, its
parameterless constructor, `EncryptAsync(Stream, Stream, Cipher, char[])`, `DecryptAsync(Stream, Stream,
char[])`, `Cipher`, `Cipher.Aes256Gcm`.

Prose symbols verified: `IPbkdf2DataEncryptionService`, `IRsaDataEncryptionService`,
`IMLKemDataEncryptionService`, `IEncryptedDataInspector`, `EncryptedDataHeader`, `DataEncryptionLimits`,
`DataEncryptionLimits.Default`, `DataEncryptionFileExtensions`, `AddEnigmaDataEncryption()`,
`DataEncryptionFormatException`, `Cipher`, `IProgress<int>`, `CancellationToken`.

### Numeric and factual claims checked against source, not memory

Every quantity either document asserts was read out of the code:

| Claim | Source | Result |
|---|---|---|
| 32-byte data key · 16-byte salt · 12-byte nonce · 128-bit tag · 16-byte key-confirmation tag | `DataEncryptionDefaults` | ✔ `DataKeySizeBytes=32`, `SaltSizeBytes=16`, `NonceSizeBytes=12`, `GcmMacSizeBits=128`, `KeyConfirmationTagSizeBytes=16` |
| PBKDF2 default 600,000 iterations | `DataEncryptionDefaults.Pbkdf2Iterations` | ✔ |
| Argon2id defaults 3 passes / 64 MiB / 4 lanes | `Argon2Iterations=3`, `Argon2MemorySizeKb=65_536`, `Argon2DegreeOfParallelism=4` | ✔ |
| Limits admit ≤ 10,000,000 PBKDF2 iterations and ≤ 1 GiB Argon2 memory | `MaxPbkdf2Iterations=10_000_000`, `MaxArgon2MemorySizeKb=1_048_576` (KiB) | ✔ |
| Format version `0x10`; `0x01`–`0x0F` reserved for legacy | `DataEncryptionDefaults.FormatVersion`, `docs/format.md` §§ 58–59, 88, 450 | ✔ |
| "twelve file-path wrappers" | `grep -c "public static Task"` in `DataEncryptionFileExtensions.cs` | ✔ 12 |
| "all five services as singletons via `TryAdd`" | `ServiceCollectionExtensions.cs` — 12 × `TryAddSingleton`, no other lifetime | ✔ |
| Every decrypt operation **and the inspector** accept stricter limits | `DataEncryptionLimits? limits = null` on all four decrypt interfaces + `IEncryptedDataInspector` | ✔ |
| Enigma.Core 1.0.0 · MEDI.Abstractions 9.0.18 | `Directory.Packages.props` | ✔ |

One claim was **wrong on first draft and corrected**: I had written that the limits stop a container from
costing you "ten million PBKDF2 iterations or a gigabyte of Argon2 memory" — but those are precisely the
values the defaults *permit*, so the sentence inverted its own point. Both files now say the cost is capped
by the reader rather than dictated by the writer, and `RELEASENOTES.md` quotes the two caps as maxima.

### Link check (AC2) — grepped, not eyeballed

The plan calls this a correctness constraint, so it was verified by command:

| Check | Command | Result |
|---|---|---|
| No relative `docs/…` link | `grep -nE '\]\(\.{0,2}/?docs/' README.md` | no match (exit 1) |
| No absolute GitHub URL | `grep -niE 'https?://[^ )]*github' README.md` | no match (exit 1) |
| Every link enumerated | `grep -oE '\]\([^)]+\)' README.md` | only `LICENSE.md` ×2, `RELEASENOTES.md`, and the 2 badge URLs + the Enigma.Core nuget.org link |
| No `CHANGELOG.md` | `ls` + `git ls-files \| grep -i changelog` | absent, untracked |

The only absolute URLs in `README.md` are `img.shields.io` (the two badge images), the badge's
`nuget.org/packages/Enigma.DataEncryption` target, and one `nuget.org/packages/Enigma.Core` link naming the
dependency. None is a GitHub URL, so the prohibition holds; all three resolve identically on nuget.org and
in the repository tree. The guides and `docs/format.md` are pointed at **in prose only**, per the rule.

`LICENSE.md` was verified as required by AC/community-files: present at the repo root (1,063 bytes, MIT,
2026 Josué Clément), named by `<PackageLicenseFile>LICENSE.md</PackageLicenseFile>`, and packed by the
`None Include="..\..\LICENSE.md" Pack="true"` item. Whether it is *actually embedded* in the artifact is
PHASE04's pack-verify, which is the right place for it.

## Documentation freshness sweep

Run as required. Candidates analysed: `CLAUDE.md`, `docs/guides/README.md`, and `docs/format.md`. The
guides index and `format.md` were assessed as **not** stale by this phase — PHASE03 wrote no API text and
duplicated no format table, and the guides' relative links are untouched.

`CLAUDE.md` had three spots this phase falsified. All three were offered and **accepted**, and are fixed in
this dev's commit:

| Spot | Was | Now |
|---|---|---|
| Project layout | `README.md, RELEASENOTES.md — Empty — written at release time (FEATURE-07DA)` | Four separate rows — `README.md` (packed landing page, prose-only docs pointers), `RELEASENOTES.md` (single release-notes source, no `CHANGELOG.md`), the new `SECURITY.md`, and `LICENSE.md` (named by `PackageLicenseFile`, packed) |
| *Conventions* → Packaging metadata | "`PackageReleaseNotes` is provisional until PHASE03 writes `RELEASENOTES.md` for it to mirror" | Records that it now mirrors `RELEASENOTES.md`, ends with the required sentence, and that the two are duplicated prose to be changed together |
| *Dev workflow* → sequence | "4 phases; PHASE01–02 done, PHASE03 next" | "4 phases; PHASE01–03 done, PHASE04 next — the release runbook and the local pack-verify" |

No other prose doc required a change.

## Deviations & follow-ups

- **No deviation from the plan's substance.** Every PHASE03 instruction was followed, including the two it
  frames as non-choices (no Downloads badge, no `CHANGELOG.md`) and the third from PHASE01 that this phase
  must not contradict (no symbol package — nothing in either document claims a `.snupkg` exists).
- **Stronger gate than asked for.** The plan permits a manual cross-check; I compiled and executed the
  snippet instead. Worth repeating in future release phases — it is cheap, and it caught nothing here only
  because the surface happened to be right.
- **`RELEASENOTES.md` structure exceeds the bare template.** The predecessor-incompatibility statement is a
  `###` subsection under *Compatibility* rather than one bullet. This is additive; the template's three
  required sections and their order are intact.
- **Line endings:** no recommendation. All four touched text files are LF-only and `.gitattributes` already
  carries `* text=auto eol=lf`, so there is no CRLF churn in this diff.
- **Follow-up for PHASE04 (not a defect):** `PackageReleaseNotes` and `RELEASENOTES.md` are now two copies
  of the same prose, kept in step only by the csproj comment and a reviewer's attention. PHASE04's
  pack-verify already inspects the nuspec's `<releaseNotes>`; that is the natural place to confirm the two
  still agree before the tag is cut.
- **Follow-up beyond this item:** the README's badge and the runbook's merge/tag/push steps assume the
  GitHub repository at `enigmalibs/Enigma.DataEncryption` exists. It is not this phase's business, but the
  NuGet badge will render as "invalid" until 1.0.0 is actually published — expected, not a defect.

## Build/test evidence

```
dotnet build Enigma.DataEncryption.slnx -c Release
  Build succeeded.  0 Warning(s)  0 Error(s)
  → netstandard2.0, net8.0, net10.0 (library) + net8.0, net10.0 (tests)

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  Test run summary: Passed!
    total: 16162   failed: 0   succeeded: 16162   skipped: 0
    net8.0  passed (12s 193ms)
    net10.0 passed (13s 245ms)
```

The csproj was edited in this phase (`PackageReleaseNotes`), so the green Release build is a real gate here
and not a formality. **No test was added or changed** — correctly so: this phase produced prose plus one
package-metadata string, and the suite already pins the wire constants (`Api/FormatConstantsTests.cs`) that
these documents quote. The snippet gate above is what covers the new prose, and it is evidenced by an
actual compile-and-run rather than a claim.

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | `README.md` follows template section order; exactly the two house badges; what's-new callout; supported-frameworks line | ✔ order verified by heading grep; 2 badges, no Downloads badge; callout at line 15; "Targets **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**; built on Enigma.Core 1.0.0" |
| 2 | No relative `docs/…` link and no absolute GitHub URL in `README.md` — **verified by grep** | ✔ both greps return no match; every link enumerated above |
| 3 | `RELEASENOTES.md` first-release section complete, with the explicit not-compatible-with-predecessor statement | ✔ *Feature overview · Compatibility · Version*, plus a dedicated `###` naming all four format changes and the reserved version range |
| 4 | `PackageReleaseNotes` mirrors the top of `RELEASENOTES.md` and ends with the required sentence | ✔ rewritten this phase; ends `See RELEASENOTES.md for the full details.` |
| 5 | `SECURITY.md` offered; created if accepted | ✔ offered, accepted, created and filled for this package |
| 6 | No `CHANGELOG.md` in the repo | ✔ absent on disk and untracked |
| 7 | README quick-start snippet re-run through the verification gate, coverage recorded | ✔ extracted verbatim, compiled (0 warnings) and executed; coverage table above, 0 mismatches |
| 8 | Zero-warning Release build; full suite green | ✔ 0 warnings; 16,162 / 16,162 passed across both test TFMs |
