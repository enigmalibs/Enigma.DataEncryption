# FEATURE-F612 — Full adversarial pre-release audit (report only)

**Status:** TODO
**Type:** FEATURE (5 phases — four review dimensions plus synthesis)
**Depends on:** FEATURE-5A30 **and** FEATURE-0D64 — both must be complete before PHASE01 starts
**Deliverable:** `docs/review/FEATURE-F612.md` — findings only; **no code, docs or config change**

## Why this is a FEATURE and not a CODE-REVIEW item

`CODE-REVIEW-HHHH` is defined by the house workflow as an item **whose phases are the findings**,
ordered highest-severity first. Findings cannot be known before the review runs, so this item — whose
phases are review *dimensions* — is a `FEATURE`, and the remediation item it produces is the
`CODE-REVIEW`. The handoff is explicit: when PHASE05 lands, its report is fed to `/interview`, which
allocates `CODE-REVIEW-????` with one severity-ordered phase per finding, built on `review/` branches.
**v1.0.0 is released only after that item's triage.**

## Objective

Establish, with independently verified evidence, whether `Enigma.DataEncryption` is correct enough to
publish — across cryptographic correctness, conformance to `docs/format.md`, the strength of the test
suite itself, and the public API / documentation / packaging surface. The output is a single
triage-ready findings report.

## Execution boundary — hard code freeze

The only files any phase of this item may create or modify:

- `docs/review/FEATURE-F612.md` (the report; **new folder** `docs/review/`, repo-only, never packed)
- `docs/roadmap.md`, `docs/plan/FEATURE-F612.md`, `docs/done/FEATURE-F612-PHASENN.md` (the workflow's
  own artifacts)

**Everything else is a finding, including typos.** A misspelling in an XML doc comment, a stale sentence
in a guide, a CRLF observation — all written up, none fixed. Verification code (a repro proving a
finding) is written in the session scratchpad and **quoted** in the report; it is never committed, and
no test is added to the suite. The reason is provenance: every change to this library must be traceable
to a finding you triaged, not to a reviewer's judgement call in an audit commit.

Running read-only commands is expected and unrestricted: `dotnet build`, `dotnet test`, coverage
collection, `git log`, `grep`. **Build/test evidence:** PHASE01 records the baseline (zero-warning
Release build plus the full suite on both test TFMs); PHASE03 additionally collects coverage to
substantiate its gap claims. PHASE02, PHASE04 and PHASE05 change no code, so they inherit PHASE01's
baseline rather than re-running the suite — state that explicitly in their completion docs, since
Definition-of-Done criteria 1–2 are satisfied by the applicable equivalent for report-only work.

**Two carve-outs, because a literal reading of the freeze would block the work it exists to enable:**

- **Temporary, reverted working-tree mutations of `src/` are permitted as verification instruments.**
  PHASE03's central question — which tests would still pass against a subtly broken implementation —
  cannot be answered by reading tests; it needs a mutation probe. So: mutate, run the affected suite,
  record which tests survived, then `git checkout --` the file. Nothing mutated is ever committed, and
  each phase's completion doc records a clean `git diff --stat` at the phase end, which is what
  acceptance criterion 6 verifies.
- **The workflow's documentation freshness sweep still runs** at the end of each phase — it is a
  question, not an edit — **but under this freeze its recommendation is always "skip".** Its named
  targets (README, `CLAUDE.md`, other prose docs) are exactly the files this item may not touch, and
  PHASE04 is chartered to hunt staleness in them, so anything it surfaces goes into the report as a
  finding and the completion doc records that the sweep ran and was skipped by design. Without this
  sentence a build agent hits the same instruction conflict five times.

## Method — fan-out, then adversarial refutation

Per phase:

1. **Find.** Spawn dimension-specific finder sub-agents, each with fresh context over a defined slice of
   the tree (the slices are listed per phase below). Each returns candidate findings with `file:line`, a
   concrete failure scenario, and a proposed severity.
2. **Refute.** Hand every candidate to **three independent verifier sub-agents, prompted to refute it**,
   each told to **default to refuted when uncertain**. Give the verifiers distinct lenses where the
   finding admits more than one failure mode (correctness / security / does-it-actually-reproduce)
   rather than three identical skeptics.
3. **Admit.** A candidate enters the report as a finding only if it survives **at least 2 of 3**
   refutation attempts. Refuted candidates go to the appendix with the refutation reasoning.

**Why this shape rather than one careful reviewer:** the repository is dense with deliberate choices
that read as defects, and `CLAUDE.md` already has to warn agents not to "fix" them. An unverified
reviewer will produce confident false positives against exactly those choices; refutation is what filters
them. Prime every finder and verifier with this list. Each entry is argued in `docs/format.md`,
`CLAUDE.md`, or the source/test file cited beside it — a candidate contradicting one of them must cite
that argument and say why it is wrong, not merely restate the observation:

- §9's **asymmetry between the two ML-KEM directions** (`Decapsulate` → `DataDecryptionException`,
  `Encapsulate` → `ArgumentException`), and the identical treatment of a wrong RSA private key and an
  undecryptable private-key PEM.
- The **absence of a public-key fingerprint field** in method `0x03` (§3.3).
- The **ML-KEM shared secret used directly as the data key**, with no KDF step (§3.4).
- **Fixed parameters kept out of the header** (§4) — and, after FEATURE-0D64, why the OAEP-hash byte is
  the documented exception rather than a contradiction.
- **Arguments validated before either file is opened**, and **the output handle closed before the
  cleanup delete** (`DataEncryptionFileExtensions`).
- **Publishing `kcTag` in the header is argued as *not* a weakening** (§6.3): an offline attacker holding
  the container can test a password guess against the header alone, and the spec explains why that costs
  nothing, since the header travels in the same file as the payload. A security finder handed PHASE01's
  key-confirmation and threat-model bullets will reach for this first.
- **The `kcTag`/AAD ordering is not circular** — §5 makes the numbered argument. Expect a candidate
  claiming it is.
- **`DataEncryptionLimits`' caps are deliberately generous, not sensible-value guidance** (§8): the
  ML-KEM cap is 4,096 against a true maximum of 1,568, because the caps are "not a statement about what
  parameters are *sensible* — only about what is *survivable*".
- **The Twofish/Serpent/Camellia payloads of the golden containers are regression vectors by design** —
  no non-BouncyCastle GCM implementation for them exists here — while their *headers* stay independent;
  the ML-KEM shared secret is likewise recovered with Enigma.Core's own KEM, and the Argon2 data key is
  pinned by OpenSSL rather than a platform primitive. All of it is stated in the suite itself
  (`Services/RsaGoldenVectorTests.cs:28-30` and the parallel notes in the PBKDF2/Argon2/ML-KEM suites and
  `GoldenVectorInventoryTests.cs`). A candidate must argue against that documented reasoning, not merely
  observe that a payload came from Enigma.Core.
- `InternalsVisibleTo` for the test assembly — argued not in the two docs but in
  `src/Enigma.DataEncryption/Properties/AssemblyInfo.cs`'s header comment (a public randomness hook in a
  cryptography library is a footgun, so the seam is internal and the test assembly gets friend access).
- Method byte `0x05` and versions `0x01`–`0x0F` reserved; **no CI workflow**, no CLI, no UI;
  `GeneratePackageOnBuild` off and **no symbol package**; `netstandard2.0` retained in the TFM set with
  PolySharp and `System.Buffers` conditioned to it alone.

Findings must be **specific and falsifiable**: a `file:line`, the input or state that triggers it, and
what goes wrong. "Consider adding defence in depth" is an Observation, not a finding.

## Report structure — `docs/review/FEATURE-F612.md`

Appended per phase, finalized in PHASE05:

```
# Code Review — Enigma.DataEncryption (pre-v1.0.0)
Date · commit reviewed · scope · method (fan-out + 3-refuter majority) · severity scale

## Executive summary            (PHASE05)
## Release gate                 (PHASE05 — which findings, if any, must block v1.0.0)
## Findings                     Critical → High → Medium → Low
   Each: ID · severity · file:line · what is wrong · failure scenario · recommended fix ·
          refutation record — one line per verifier: its lens (correctness / security /
          reproducibility), its verdict (refuted / not refuted) and its one-line reasoning,
          then the strongest surviving counter-argument. Three lens-labelled verdicts, or
          the finding is not admissible — an aggregate "survived 3/3" is unauditable.
## Observations                 informational only — deliberately NOT phases of the CODE-REVIEW item
## Considered and refuted       what was suspected, and why it is actually correct
## Coverage statement           what each dimension examined, and what it consciously did not
```

**Severity scale:** `Critical` / `High` / `Medium` / `Low` for actionable findings — these map 1:1 onto
`CODE-REVIEW` phases — plus **Observations**, which do not become phases. The boundary is a real
judgement call and belongs to the reviewer: if you would not open a branch for it, it is an
Observation. Anything about line endings is an Observation by house rule, never a finding.

---

## PHASE01 — Cryptographic & security correctness

**Status:** TODO
**Suggested branch:** `feature/feature-f612-phase01-crypto`
**Slice:** `src/Enigma.DataEncryption/Services/`, `src/Enigma.DataEncryption/Internal/`,
`Exceptions/`, `DataEncryptionDefaults.cs`, `DataEncryptionLimits.cs`

Check against the normative sources, not against intuition: **RFC 8017** (RSAES-OAEP), **RFC 8018**
(PBKDF2), **RFC 9106** (Argon2id), **FIPS 203** (ML-KEM), **NIST SP 800-38D** (GCM nonce and tag
requirements).

- **Key material lifetime** — every data key, `kcKey`, derived buffer and UTF-8 password encoding
  cleared in a `finally` that encloses *every* use, on every exception path. Include the paths that are
  easy to miss: the wrapped-key length-mismatch rejection, a cancelled operation, a failed header write,
  and `PasswordCredential`'s intermediate buffers.
- **Randomness** — `IRandomSource`/`RandomSource` is a CSPRNG on every TFM; the test seam cannot be
  reached in production; no derived value is reused as a nonce.
- **Nonce and key uniqueness** — 12 random bytes per container against SP 800-38D's guidance for random
  nonces; specifically, whether *password* methods can produce a (key, nonce) collision more cheaply
  than the birthday bound suggests, given the 16-byte salt and a reused password.
- **AEAD binding** — the complete header as AAD in both directions, and that the reader's tee makes the
  AAD definitionally the bytes on the wire; 128-bit tag; `PaddingScheme.None`.
- **Key confirmation** — `kcKey` derivation, the 27-byte label, truncation to the leftmost 16 bytes,
  and that verification is **constant-time** and happens **before any payload byte is read** in all
  four (five, post-5A30) methods.
- **`CryptoHelpers.FixedTimeEquals`** — genuinely constant-time on **every** TFM, including the
  `netstandard2.0` path where the platform intrinsic is unavailable. This is the single highest-value
  target in the phase.
- **Ordering invariants** — limits validated before any allocation or KDF work (§7.2 step 3); argument
  validation before any stream is touched; cancellation observed before writes.
- **Exception translation** — matches §9 exactly, and **never** distinguishes causes by matching on
  message text.
- **Default cost parameters** (§4.1) — still defensible against current PBKDF2 / Argon2id guidance for
  2026, and the limits (`MaxPbkdf2Iterations` etc.) actually bound a hostile header.
- **ML-KEM implicit rejection** — a wrong private key is caught by the tag, not by decapsulation, and no
  payload byte is read first.
- **Post-5A30 addition** — the hybrid key combiner: does it hold the "secure if **either** input is
  secure" property, is it bound to both ciphertexts, and do the two "one credential wrong" tests
  actually prove both inputs contribute.
- **Threat-model statement** — what the format deliberately does *not* provide (sender authentication,
  length hiding, metadata privacy, replay protection). Anything absent *and* undocumented is a finding
  against the docs; absent *and* documented is neither.

**Evidence to record:** the baseline zero-warning Release build and full-suite result on both test TFMs,
with the commit SHA.

---

## PHASE02 — `docs/format.md` conformance

**Status:** TODO
**Suggested branch:** `feature/feature-f612-phase02-format`
**Slice:** `docs/format.md` against `Internal/` (writer, reader, layout, wire mappings, validators),
`EncryptedDataHeader.cs`, `Cipher.cs`, `EncryptionMethod.cs`, `Api/FormatConstantsTests.cs`

Check **both directions** — a spec clause the code does not honour, *and* a behaviour the code has that
the spec does not license. Every offset, size, constant and rule in **§1.1** (integer encoding — the spec
itself flags the byte-order rule as "the single most likely source of a silent interop defect"), **§1.2**
(offsets are absolute and zero-based), §2, §3.1–3.4 (§3.5 post-5A30), §4, §4.1, §5, §6, §7.1, §7.2, §8,
§9, §10.

- Header lengths and field offsets for every method, including the two post-FEATURE-0D64 and
  post-FEATURE-5A30 shapes.
- `Int32` little-endian reads and writes — **explicitly on a big-endian host**: does the code use
  endian-explicit primitives, or does it inherit `BitConverter`'s host order? If the format says LE, a
  big-endian platform must still produce LE.
- Wire-value mappings are explicit and never cast (`MLKemParameterSetWire`, `RsaOaepHashWire`), and every
  reserved or undefined value is rejected: method `0x05` before 5A30 lands, versions `0x01`–`0x0F`, the
  parameter-set byte `0x00`/`0x04`+, the OAEP-hash byte `0x00`/`0x01`/`0x05`+.
- Which spec clauses `FormatConstantsTests` actually pins, and which are unpinned prose that could drift
  silently — the gap itself is a finding if it covers something load-bearing.
- The inspector's guarantee (§9) that a header-only reader raises the **format** half alone and reports
  an edited-but-valid cipher or parameter byte as it found it.
- Non-seekable input streams (§7.2's closing claim) and forward-only single-pass header reads.
- Error **messages** as well as types: a message that names the wrong cause misleads exactly when it
  matters, and the XML docs are part of the contract.

---

## PHASE03 — Test-suite quality & coverage gaps

**Status:** TODO
**Suggested branch:** `feature/feature-f612-phase03-tests`
**Slice:** all of `tests/Enigma.DataEncryption.UnitTests/`, plus a coverage run

A large green suite is not the same as an adversarially strong one. The question this phase answers is:
**which tests would still pass against a subtly broken implementation?** (Answering it needs the mutation
carve-out in the *Execution boundary* — probe, record, revert.)

**Re-measure before reasoning.** The last recorded figures are 16,162 tests at 97.43% line / 90.82%
branch (`docs/done/FEATURE-11B6-PHASE05.md`, `docs/done/FEATURE-07DA-PHASE04.md`) with ~2,600 sweep
containers per TFM — but this item depends on `FEATURE-5A30` and `FEATURE-0D64`, and **both add tests and
extend the sweep**. Those numbers are a pre-dependency baseline, not the audited state; measure at the
audited commit and reason about what you measure.

- **Tautological assertions** — round-trips that would survive a broken KDF (encrypt and decrypt agreeing
  on the same wrong value), tag checks that never see a wrong tag, "does not throw" tests standing in
  for behavioural assertions.
- **Golden-vector integrity** — every committed vector genuinely computed by an **external** oracle
  (Python `hashlib`/`hmac`, OpenSSL `ARGON2ID`, the platform `AesGcm`) rather than by this library, since
  a self-derived vector pins the implementation instead of the format. **This is a finding only where the
  suite does not already document why no external oracle exists** — the Twofish/Serpent/Camellia payloads
  are declared regression vectors and the ML-KEM shared secret is necessarily recovered with Enigma.Core's
  KEM (see the priming list). An *undocumented* self-derived vector, or a documented one whose note is no
  longer true, is the finding. Verify the fixture inventory (`GoldenVectorInventoryTests`) matches what is
  committed, and that each fixture still decrypts to the expected plaintext.
- **Coverage gaps** — collect coverage and enumerate the uncovered lines and branches; judge each
  (unreachable defensive code is fine and should be said so; an uncovered failure path is a finding).
- **Depth of existing coverage** — these are already covered; judge whether the coverage is *adequate*,
  and do not report them as gaps: zero-length payloads (`PasswordRoundTripTests.RoundTripsAnEmptyPayload`),
  non-seekable and slow streams (`TestStreams.ForwardOnlyStream`, `CanSeek => false`, 1-byte chunks),
  cancellation observed mid-payload (`PasswordCancellationTests`, both directions), and one service
  instance under concurrency (`ServiceThreadSafetyTests`, 32 tasks against a single instance).
- **Negative space** — genuinely uncovered as of the last audit of the suite: an `IProgress<int>`
  implementation that **throws** (the only doubles, `ProgressCollector` and `SynchronousProgress`, never
  do), a **big-endian host**, the **`netstandard2.0`-only polyfill paths** (`CLAUDE.md` claims they are
  exercised indirectly through the `net8.0` paths — is that actually true?), and payloads spanning
  multiple buffer boundaries.
- **Determinism** — no test depends on wall-clock time, ambient randomness, machine parallelism or file
  ordering; theory data is deterministic across runs and TFMs.
- **Signal density** — how much of the measured test count is genuinely distinct versus combinatorial
  expansion, and whether the malformed-input sweep's containers actually assert something the targeted
  tests do not.
- **Runner configuration** — the MTP-native setup (no `Microsoft.NET.Test.Sdk`, no
  `xunit.runner.visualstudio`) and whether a failure could be silently skipped rather than reported.

**Evidence to record:** the coverage numbers, the exact commands, and the uncovered-region list. Use:

```
dotnet build Enigma.DataEncryption.slnx -c Release
dotnet test --solution Enigma.DataEncryption.slnx -c Release
dotnet test --solution Enigma.DataEncryption.slnx -c Release -- --coverage --coverage-output-format cobertura
```

The `--solution` flag is required (the .NET 10 SDK in MTP mode rejects `dotnet test <Solution>.slnx`), and
**coverage comes from `Microsoft.Testing.Extensions.CodeCoverage`, not `coverlet.collector`** — the latter
is a VSTest data collector that registers nothing with an MTP runner. `FEATURE-11B6` PHASE05 lost time to
exactly that dead end; `Directory.Packages.props` carries the explanation in a comment. Note also that
`CLAUDE.md` still lists the test-only packages as "`xunit.v3`, `coverlet.collector`, …" in two places and
omits the coverage extension that actually works — a **candidate finding for PHASE04**, recorded here so
PHASE03 does not silently work around it.

---

## PHASE04 — Public API, documentation & packaging

**Status:** TODO
**Suggested branch:** `feature/feature-f612-phase04-api-docs`
**Slice:** every exported type; `docs/guides/*`, `README.md`, `RELEASENOTES.md`, `SECURITY.md`,
`LICENSE.md`, `CLAUDE.md`; `Directory.Build.props`, `Directory.Packages.props`, `global.json`,
`.editorconfig`, both csproj files, `docs/RELEASE.md`

- **Surface** — nullable annotations correct and meaningful; no BouncyCastle type anywhere on an
  exported member (the reflection guard covers signatures — check what it *cannot* see, such as an
  exception type thrown out of a public method); no `Internal/` type exported; async signatures
  consistent; optional-parameter defaults sensible; naming consistent across the five services.
- **XML docs as contract** — every documented `<exception>` actually thrown, and every exception a
  member can throw either documented or deliberately not; no doc comment describing behaviour the code
  does not have. This is where documentation drift becomes a real defect.
- **Guides** — all six re-verified snippet by snippet against the real public surface of **both** this
  library and Enigma.Core. There is no permanent doc-sample test project, so this pass is the only gate
  that has ever checked them. Also: no wire-format table duplicated out of `docs/format.md`, and
  relative links (including `../format.md`) still correct given the guides are repo-only and never
  packed.
- **Packed prose** — `README.md` has no clickable `docs/…` link (it is packed; the guides are not);
  `RELEASENOTES.md` and the csproj `PackageReleaseNotes` still agree, and the csproj comment binding
  them is intact; `SECURITY.md`'s private-reporting instructions are accurate; `LICENSE.md` is named by
  `PackageLicenseFile` and actually packs.
- **Packaging** — all 12 NuGet properties present and correct for a 1.0.0 first release;
  `GeneratePackageOnBuild` off and no symbol properties (both deliberate — confirm, don't "fix");
  `None` items pack `README.md` and `LICENSE.md`; CPM holds every version with **no** `Version=` on any
  `PackageReference`; `System.Buffers` and PolySharp conditioned to `netstandard2.0` alone (NU1510);
  the test-only `Microsoft.Extensions.DependencyInjection` has not migrated into the library, which
  still depends on the Abstractions alone.
- **Build enforcement** — `TreatWarningsAsErrors` and `EnforceCodeStyleInBuild` genuinely in force for
  both projects and all TFMs; `.editorconfig` severities not silently downgraded; `global.json`'s SDK
  pin and MTP runner setting still match the documented commands.
- **Licence position** — Enigma.Core's and, transitively, BouncyCastle's licences against what this
  package ships and states; whether any attribution obligation is unmet.
- **Release readiness** — `docs/RELEASE.md` still describes a runbook that would work, given whatever
  FEATURE-5A30 and FEATURE-0D64 changed.
- **`CLAUDE.md` accuracy** — it overrides agent behaviour, so a stale claim in it is a real defect, not
  a cosmetic one.

---

## PHASE05 — Synthesis, severity calibration & triage handoff

**Status:** TODO
**Suggested branch:** `feature/feature-f612-phase05-synthesis`

The four dimensions run independently and will not agree on severity, so this phase is where the report
becomes a single document:

- **Deduplicate** across dimensions. A spec/code disagreement that is also a test gap and also a doc
  error is **one** finding with three symptoms, not three findings — otherwise the `CODE-REVIEW` item
  gets three phases that all touch the same line.
- **Recalibrate severity globally**, with one consistent yardstick applied to every finding, and record
  the yardstick in the report so the ranking can be argued with.
- **Write the executive summary** — what was audited, how, what was found, and the honest shape of the
  result.
- **Write the release gate** — the explicit list of findings that must be fixed before v1.0.0 is
  published, and the reasoning. This is a *recommendation*; the release decision stays with the
  maintainer.
- **Consolidate** the Observations and the Considered-and-refuted appendix, dropping duplicates.
- **Write the coverage statement** — per dimension, what was examined and what was consciously not, so
  the report can never be mistaken for broader than it is.
- **Confirm the report is self-contained** enough to paste into `/interview` and produce a
  `CODE-REVIEW-????` item with one severity-ordered phase per finding and nothing lost.

---

## Acceptance criteria

1. All five phases complete, each with its own completion doc under `docs/done/`.
2. `docs/review/FEATURE-F612.md` exists and follows the structure above, including the Observations
   section, the Considered-and-refuted appendix and the per-dimension coverage statement.
3. **Every reported finding survived at least 2 of 3 independent refutation attempts**, and its
   refutation record lists **each** verifier's lens, verdict and one-line reasoning, plus the strongest
   surviving counter-argument. A finding whose record shows fewer than three lens-labelled verdicts is
   not admissible — that is what makes this criterion checkable by a reader of the report.
4. Every finding carries a severity, a `file:line`, a concrete failure scenario and a recommended fix.
5. PHASE05 has deduplicated across dimensions, recalibrated severity globally, and produced the
   executive summary and the release-gate recommendation.
6. **No file outside `docs/review/`, `docs/roadmap.md`, `docs/plan/` and `docs/done/` has been
   modified** — verifiable with `git diff --stat` against the branch point of each phase. PHASE03's
   mutation probes are reverted before the phase ends, so this holds for them too; each completion doc
   records the clean `git diff --stat`.
7. The audited commit builds warning-free and the full suite passes on both test TFMs (recorded in
   PHASE01, with the SHA), and PHASE03 records coverage **measured at the audited commit**, not the
   pre-dependency figures quoted in this plan.
8. The report is self-contained enough to hand to `/interview` for the `CODE-REVIEW-????` item.

## Follow-up — not planned here

`/interview` on this report mints `CODE-REVIEW-????`: one phase per actionable finding, ordered
Critical → High → Medium → Low, built on `review/` branches. **Then** the maintainer runs
`docs/RELEASE.md` for v1.0.0. Observations do **not** become phases; promote one only by deciding to.

## If this is dropped

Mark the row `ABANDONED` with a reason. If any phase has already produced findings, keep
`docs/review/FEATURE-F612.md` in the repository rather than deleting it — a partial audit that says what
it covered is worth more than no audit, and the release gate would then be an explicitly unaudited one.
