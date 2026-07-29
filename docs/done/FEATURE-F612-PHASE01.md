# FEATURE-F612 PHASE01 — Cryptographic & security correctness

**Completed:** 2026-07-29
**Branch:** `feature/feature-f612-phase01-crypto`, cut from `develop` at
`b1ab2c2918cb569fcec1de9ef7bdce92b7039972`
**Deliverable:** `docs/review/FEATURE-F612.md` — created, PHASE01 section complete

## Summary

The first of `FEATURE-F612`'s four review dimensions. Audited the cryptographic and security correctness
of `Services/`, `Internal/`, `Exceptions/`, `DataEncryptionDefaults.cs` and `DataEncryptionLimits.cs`
against RFC 8017, RFC 8018, RFC 9106, FIPS 203, NIST SP 800-38D and `docs/format.md`, and wrote the
findings report. **No code, test, spec or prose file was changed** — this item is report-only, under a
hard code freeze.

Method, as the plan prescribes: **8 dimension finders → 32 candidates → 20 deduplicated claims → 60
lens-labelled refuters (correctness / security / reproducibility, each defaulting to refuted) → 10
admitted, 10 refuted.** Every admitted finding carries three lens-labelled verdicts with verbatim
reasoning and the strongest surviving counter-argument, so acceptance criterion 3 is checkable by a
reader of the report.

**Result: 3 Medium, 7 Low. No Critical, no High.** The refutation pass moved three candidates down from
a proposed High and rejected half of everything found — including two claims that would have sent a
maintainer to reverse a documented, tested policy decision (deliberate choice 8's generous caps) and one
that rested on misreading §7.1 step 2 as non-normative.

The three Mediums:

- **F01** — streaming decryption releases the whole payload as unverified, attacker-bit-flippable
  plaintext before the GCM tag is checked, and the word *unauthenticated* appears nowhere in the
  repository. Threshold measured exactly: `floor(size/4096)*4096` bytes released.
- **F02** — every nonce, salt and RSA data key comes from a `[ThreadStatic]` BouncyCastle
  `DigestRandomGenerator` that is OS-seeded once and never reseeded, so live process-state duplication
  repeats the byte sequence. A verifier **demonstrated** the resulting (key, nonce) reuse by restoring the
  generator state and recovering one plaintext from another. One-line local fix.
- **F03** — `EncryptFileAsync(p, p, …)` **deletes the caller's file**, because `RunAsync`'s cleanup
  `catch` also covers failures that created nothing — a case the remarks at
  `DataEncryptionFileExtensions.cs:617-620` claim is "the one case that must not delete anything" while
  handling only the other one.

## Files touched

Created:

- `docs/review/FEATURE-F612.md` — the findings report (new folder `docs/review/`, repo-only, never
  packed).
- `docs/done/FEATURE-F612-PHASE01.md` — this record.

Modified:

- `docs/roadmap.md` — `FEATURE-F612` → `IN PROGRESS`; `PHASE01` → `IN PROGRESS` then `DONE`.
- `docs/plan/FEATURE-F612.md` — item and PHASE01 status.

**Nothing else.** No file under `src/`, `tests/`, `docs/format.md`, `docs/guides/`, `README.md`,
`CLAUDE.md`, `RELEASENOTES.md`, `SECURITY.md` or any csproj was created, modified or deleted.

## Build/test evidence

**Baseline recorded at the audited commit** (acceptance criterion 7), before any analysis:

```
$ dotnet build Enigma.DataEncryption.slnx -c Release
Build succeeded.
    0 Warning(s)

$ dotnet test --solution Enigma.DataEncryption.slnx -c Release
Test run summary: Passed!
  total:     28272
  failed:        0
  succeeded: 28272
  skipped:       0
```

Both test TFMs (`net8.0`, `net10.0`), at SHA `b1ab2c2918cb569fcec1de9ef7bdce92b7039972`. The audited
commit builds warning-free and the whole suite passes, so every finding is a defect the green suite does
not detect; the report records why in each case.

PHASE01 changed no code, so no re-run was needed after the audit. PHASE02, PHASE04 and PHASE05 inherit
this baseline per the plan; PHASE03 additionally collects coverage.

**Execution boundary verified** (acceptance criterion 6), at the end of the phase:

```
$ git diff --stat b1ab2c2
 docs/plan/FEATURE-F612.md | 4 ++--
 docs/roadmap.md           | 4 ++--
 2 files changed, 4 insertions(+), 4 deletions(-)

$ git status --porcelain
 M docs/plan/FEATURE-F612.md
 M docs/roadmap.md
?? docs/review/FEATURE-F612.md
```

No `src/` or `tests/` path appears. The mutation carve-out was not used: PHASE01 needed no mutation probe,
so no `src/` file was altered even temporarily.

**Verification instruments.** 13 probes by the lead plus independent harnesses per verifier, all in the
session scratchpad, referencing
`src/Enigma.DataEncryption/bin/Release/net10.0/Enigma.DataEncryption.dll` directly rather than through a
`ProjectReference`, so the library was never rebuilt. Nothing was committed and no test was added. The
outputs are quoted in the report beside the findings they establish. Dependency behaviour that a finding
turned on was settled by `ilspycmd` decompilation of the shipped Enigma.Core and BouncyCastle assemblies
rather than by intuition, and the report says so at each point.

## Deviations & follow-ups

**Deviations from the plan**

- **The plan lists seven bullets for PHASE01; the fan-out used eight finder dimensions**, splitting
  "randomness" from "nonce and key uniqueness" so the RNG's construction and the (key, nonce) arithmetic
  got independent attention. F02 came out of that split.
- **The plan's `docs/review/FEATURE-F612.md` skeleton puts the executive summary and release gate
  first.** Both are present as explicit PHASE05 placeholders rather than written now, since PHASE05 owns
  them and writing them per-phase would guarantee they contradict each other.
- **`docs/format.md` was read in full by every finder**, which the plan assigns to PHASE02. That is
  unavoidable — §9 conformance is a PHASE01 bullet — and produces deliberate overlap for PHASE05 to
  deduplicate. PHASE01 did **not** check offsets, sizes or golden-vector bytes; the coverage statement
  says so.
- **F03 is outside PHASE01's nominal slice** (`DataEncryptionFileExtensions.cs`). It surfaced while the
  file-handle and cleanup ordering was being read as supporting evidence for the ordering dimension. It is
  reported where it was found, flagged in the report for PHASE05 to re-home.

**Plan drift noticed, not acted on**

- **PHASE04's slice says "all six [guides]"; there are seven** (`hybrid.md` was added by
  `FEATURE-5A30`). Worth correcting in the plan before PHASE04 runs, so its coverage claim is accurate.
- PHASE03's quoted baseline ("16,162 tests at 97.43% line / 90.82% branch, ~2,600 sweep containers") is
  correctly labelled pre-dependency in the plan. For reference, the audited commit is at **28,272 tests**.

**Forwarded to later phases**

- **PHASE04**: F04 additionally requires correcting `docs/guides/hybrid.md:62-63`, which claims the RSA
  half "takes any modulus size Enigma.Core will generate" — false below a 98-byte modulus. O04 records two
  stale XML doc comments (`EncryptedDataInspector.cs:32-33` says the inspector "reads all four" methods;
  `HybridKeyCombiner`'s remarks misattribute the header-slice assertion to `HybridKeyCombinerTests`
  instead of `HeaderGoldenBytesTests`).
- **PHASE03**: three concrete test gaps, each with the reason the green suite misses the defect. The
  tamper tests use 200- and 256-byte payloads, below F01's 4,096-byte threshold, and never inspect
  `output.Length` — all nine `Assert.Equal(0, output.Length)` assertions sit on wrong-credential paths.
  `HybridKeyFixture` generates no undersized RSA key, which is why F04 is invisible. No test bounds any
  encrypt-side cost argument above zero (O01). Also relevant to PHASE03's negative-space list: a throwing
  `IProgress<int>` was reproduced to propagate `InvalidOperationException` raw out of both directions,
  with 4,096 bytes already released on decrypt.
- **PHASE05**: F03's severity is the one place PHASE01 declined to settle. Two verifiers said Medium and
  one Low, all noting there is no adversary; the countervailing consideration is silent, unrecoverable
  loss of user data from a single plausible call. Whether a non-security defect of that shape outranks the
  security-relevant Mediums is a global yardstick question.

**Documentation freshness sweep** — ran, and skipped by design. Under this item's code freeze its named
targets (`README.md`, `CLAUDE.md`, other prose docs) are exactly the files this item may not touch, and
PHASE04 is chartered to hunt staleness in them, so what the sweep surfaced went into the report as F04's
guide error and O04 rather than into an edit. The plan anticipates this explicitly.

**Line endings** — no CRLF/LF inconsistency was observed in any file read. Recorded per the house rule
that anything about line endings is an Observation and never a finding.

## Next

PHASE02 — `docs/format.md` conformance, on `feature/feature-f612-phase02-format`. It inherits this
baseline rather than re-running the suite, and should read PHASE01's *verified clean* list first: the
`kcTag`/AAD ordering, the tee-ed AAD, the combiner transcript's equality with the header slice, and §9's
row-by-row diff are already done and need not be redone.
