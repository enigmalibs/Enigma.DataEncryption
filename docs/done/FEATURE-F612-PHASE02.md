# FEATURE-F612 PHASE02 — `docs/format.md` conformance

**Completed:** 2026-07-29
**Branch:** `feature/feature-f612-phase02-format`, cut from
`feature/feature-f612-phase01-crypto` at `e36df1ecd36723bb4d179243a84168a8b7b1d50e`
**Deliverable:** `docs/review/FEATURE-F612.md` — PHASE02 section appended

## Summary

The second of `FEATURE-F612`'s four review dimensions. Audited the agreement between the normative
specification `docs/format.md` and the code, **in both directions** — a spec clause the code does not
honour, *and* a behaviour the code has that the spec does not license — across §§1.1, 1.2, 2–2.4,
3.1–3.5.2, 4, 4.1, 5, 6–6.3, 7.1, 7.2, 8, 9 and 10. **No code, test, spec or prose file was changed** —
this item is report-only, under a hard code freeze.

Method, as the plan prescribes: **10 dimension finders → 32 candidates → 18 deduplicated claims → 54
lens-labelled refuters (correctness / spec authority / reproducibility, each defaulting to refuted) → 9
admitted, 9 refuted**, plus 5 finder-proposed Observations routed to the report without refutation on
PHASE01's O04/O05 precedent. Every admitted finding carries three lens-labelled verdicts with verbatim
reasoning and the strongest surviving counter-argument, so acceptance criterion 3 is checkable by a
reader of the report.

**Result: 2 Medium, 7 Low. No Critical, no High.** Findings are numbered `F11`–`F19`, Observations
`O06`–`O12`, refuted candidates `R08`–`R14`, continuing PHASE01's numbering so PHASE05 can merge without
renumbering.

The two Mediums are the only findings with a consequence beyond prose:

- **F11** — a tampered method `0x03` container built with an RSA modulus of 98–128 bytes throws an
  unwrapped `System.IndexOutOfRangeException` out of `DecryptAsync`. BouncyCastle's `OaepEncoding.DecodeBlock`
  over-reads when `(modBits − 1)/8 < 2·hLen`; that is not a `CryptoException`, so Enigma.Core's
  `PublicKeyService.Transform` does not translate it and `UnwrapDataKey`'s `catch (CryptographicException)`
  does not see it. The window is exactly RSA-1024 and below — a size the library explicitly blesses under
  SHA-256. `MalformedContainerSweepTests.cs:470` asserts `IsNotType<IndexOutOfRangeException>` **verbatim**;
  the sweep misses this only because its RSA harness uses the committed 2048-bit fixture.
- **F12** — §3.3 pins RSAES-OAEP's hash but neither its **mask-generation function** nor its **label**.
  `grep -i "mgf\|mask.gener"` returns zero hits across `docs/format.md`, `docs/guides/` and `src/`. RFC 8017
  makes `maskGenAlgorithm` a free parameter whose ASN.1 default is `mgf1SHA1`, so an implementer following
  the cited standard's own default lands on the incompatible reading. Demonstrated end to end by splicing a
  MGF1-SHA-1 wrap into a container byte-identical at every offset the spec states.

The seven Lows are documentation and pinning defects, five of them in **shipped public XML** or in the
**spec contradicting itself**: `Cipher`'s remark still claims the cipher is the only algorithmic degree of
freedom (F13); `DataEncryptionDefaults` says `FormatVersion` is "not stored in the container header"
(F14); §2.4/§4 count exactly two algorithmic fields when the ML-KEM parameter-set byte is a third (F15);
the password's character encoding is nowhere stated (F16); the Serpent/Camellia cipher mapping is unpinned
— swapping the two factory calls leaves all 28,272 tests green (F17); `ReadRsaBodyAsync`'s remark says an
edited offset-5 byte "does not fail here" nine lines above the statement that rejects 253 of 255 edits
(F18); and `LimitsValidator`'s XML puts the hybrid's encapsulation length at the wrong offset (F19).

**Two guards were set deliberately, and both fired.** C01 — encrypt-side cost parameters bounded only at
`> 0` — was raised independently by **4 of 10 finders**, one at High, and is a re-dressing of PHASE01's
**O01**. Its verifiers were handed PHASE01's verbatim refutation reasoning and told that re-admitting a
PHASE01 observation on a new argument that does not hold would be a real failure of this audit; they
refuted it **3 of 3** on the document's own structure. C14 was likewise refuted as a duplicate of PHASE01's
**F05**. Without those guards this phase would have reported two findings that PHASE05 would have had to
withdraw.

**The larger half of the result is negative, and the report says so at length.** Every offset in §§3.1–3.5
was verified on real bytes and on committed fixtures; §1.1's little-endian rule holds on a big-endian host
(Enigma.Core's `WriteInt`/`ReadInt` decompile to literal shift expressions, byte-identical across all three
shipped TFMs, not `BitConverter`); the rejection matrix is complete across every reserved and undefined
wire value; §5's "the AAD is exactly the header, and exactly once" is true by measurement (25 of 25 exact);
§7.2's non-seekable forward-only single-pass claim holds with no over-read by even one byte; and all
fourteen committed fixtures are conformant and decrypt to the golden plaintext.

## Files touched

Modified:

- `docs/review/FEATURE-F612.md` — PHASE02 section appended (+1,821 lines); the status header updated to
  record the running total across both phases.
- `docs/roadmap.md` — `PHASE02` → `IN PROGRESS` then `DONE`.
- `docs/plan/FEATURE-F612.md` — PHASE02 status, with the finding count.

Created:

- `docs/done/FEATURE-F612-PHASE02.md` — this record.

**Nothing else.** No file under `src/`, `tests/`, `docs/format.md`, `docs/guides/`, `README.md`,
`CLAUDE.md`, `RELEASENOTES.md`, `SECURITY.md` or any csproj was created, modified or deleted.

## Build/test evidence

**PHASE02 changed no code, so it inherits PHASE01's baseline rather than re-running the suite** — which
the plan's *Execution boundary* section prescribes explicitly, and which Definition-of-Done criteria 1–2
are satisfied by as the applicable equivalent for report-only work.

That inheritance is sound here for a stronger reason than the plan's general rule: the audited *library*
code at this phase's branch point (`e36df1e`) is **byte-identical** to the code PHASE01 measured at
`b1ab2c2`. `e36df1e` is PHASE01's own commit, and it added only `docs/review/FEATURE-F612.md` plus the two
workflow artifacts. The recorded baseline therefore still describes the audited commit:

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

Both test TFMs (`net8.0`, `net10.0`). The 28,272 figure was independently re-confirmed during this phase:
two verifiers ran the full suite on scratchpad copies of `HEAD` as the control arm of F17's mutation
experiment, and the unmutated control reported `total: 28272 / failed: 0` on both occasions.

Every finding below is therefore a defect the green suite does not detect, and each records why. F11 is
the sharpest case — the suite states the exact invariant it violates (`IsNotType<IndexOutOfRangeException>`)
and misses it on key size alone.

**Execution boundary verified** (acceptance criterion 6), at the end of the phase:

```
$ git diff --stat e36df1e
 docs/plan/FEATURE-F612.md   |    2 +-
 docs/review/FEATURE-F612.md | 1821 ++++++++++++++++++++++++++++++++++++++++++-
 docs/roadmap.md             |    2 +-
 3 files changed, 1821 insertions(+), 4 deletions(-)

$ git status --porcelain
 M docs/plan/FEATURE-F612.md
 M docs/review/FEATURE-F612.md
 M docs/roadmap.md
```

(plus the untracked `docs/done/FEATURE-F612-PHASE02.md` written after this snapshot). No `src/` or
`tests/` path appears.

**The mutation carve-out was not used, and did not need to be.** PHASE03 owns it; PHASE02 does not have it.
F17's two mutation experiments — swapping the Serpent and Camellia arms of `CipherResolver.Resolve`, with a
Twofish/Serpent control — were run on `git archive HEAD | tar -x` copies inside the session scratchpad, so
**no `src/` file in the repository was altered even temporarily**.

**Verification instruments.** Ten finder harnesses plus independent per-verifier probes, all in the session
scratchpad, referencing
`src/Enigma.DataEncryption/bin/Release/net10.0/Enigma.DataEncryption.dll` directly rather than through a
`ProjectReference`, so the library was never rebuilt. Nothing was committed and no test was added. The
outputs are quoted in the report beside the findings they establish. Notable instruments, because they are
what makes this phase's negative results worth trusting:

- **Two independent spec-only readers** — a Python header parser and a BCL-only C# decryptor
  (`Rfc2898DeriveBytes`, `HMACSHA256`, `AesGcm`, `RSA.ImportFromPem`, plus OpenSSL 3.6.3 `ARGON2ID` for
  §3.2) — both written from `docs/format.md` alone with no reference to the library's source, run against
  all fourteen committed fixtures; plus a spec-only **writer** whose output was handed back to the
  library's readers. This is how F12 was isolated.
- A **3,281-line byte-edit sweep** recording exception type and message from both `DecryptAsync` and
  `ReadHeaderAsync` for every value of every selector byte on every method.
- RSA containers generated at fifteen modulus sizes from 776 to 4096 bits under all three OAEP hashes,
  which is what pinned F11's boundary.
- A counting-stream probe over a genuinely non-seekable input, which established both §7.2's
  no-over-read property and O06's allocation ordering.

Dependency behaviour that a finding turned on was settled by `ilspycmd` decompilation of the shipped
Enigma.Core and BouncyCastle assemblies rather than by intuition — including `StreamExtensionsInt32` on
**all three TFMs** for the endianness question and `OaepEncoding.DecodeBlock` /
`RsaCoreEngine.GetOutputBlockSize` for F11 — and the report says so at each point.

## Deviations & follow-ups

**Deviations from the plan**

- **The plan lists seven bullets for PHASE02; the fan-out used ten finder dimensions.** The extra three
  split method `0x03` from methods `0x04`/`0x05` (they were changed by different items and have different
  hazards), gave the `FormatConstantsTests` pinning question its own finder, and — the one that paid off
  most — assigned a finder to the **reverse direction alone**, forbidden to walk the spec and required to
  write spec-only implementations instead. F12 came out of the reverse-direction work.
- **Five finder-proposed Observations were not put through refutation** (O08–O12), on the precedent
  PHASE01 set with O04 and O05. Each is flagged as such in the report. All eighteen claims proposed at Low
  or above were refuted in full.
- **PHASE02 reports four XML-doc defects** (F13, F14, F18, F19), which reads like PHASE04's dimension. Each
  is here because it contradicts a specific `docs/format.md` clause, which is PHASE02's dimension; the
  general XML-docs-as-contract sweep remains PHASE04's. Flagged in the report's coverage statement for
  PHASE05 to re-home if it disagrees.
- **F17 straddles PHASE03.** A pinning gap is normally test-suite quality, but this one covers a normative
  §2.4 wire clause, so it is reported here and flagged for PHASE05.

**Plan drift noticed, not acted on**

- **PHASE04's slice still says "all six [guides]"; there are seven.** PHASE01's completion doc already
  raised this and it is still uncorrected. Worth fixing in the plan **before PHASE04 runs**, so its coverage
  claim is accurate.
- PHASE03's quoted baseline (16,162 tests, 97.43% line / 90.82% branch, ~2,600 sweep containers) remains
  correctly labelled pre-dependency. The audited commit is at **28,272 tests**, re-confirmed twice this
  phase.

**Forwarded to later phases**

- **PHASE03** — four concrete test gaps, each with the reason the green suite misses the defect.
  (1) `MalformedContainerSweepTests`' RSA harness is hardcoded to the committed 2048-bit fixture
  (`ContainerMethodHarness.cs:415`), which is the sole reason F11 is invisible; one sub-2048 modulus in the
  sweep would have caught it. (2) Nothing binds `Cipher.Serpent256Gcm` to `CreateSerpentService` or
  `Cipher.Camellia256Gcm` to `CreateCamelliaService` — a swap leaves all 28,272 tests green (F17), and the
  fix is a four-line test with an injected recording factory, which deliberate choice 9 does **not**
  preclude. (3) No test could distinguish a §1.1-conforming little-endian writer from a host-order one
  (O09). (4) `FormatConstantsTests.HeaderLengths_MatchTheSpecification` is a parallel re-derivation that
  does not pin `FormatLayout`; the real pin is in `FormatLayoutTests` (O08).
- **PHASE04** — O08's `CLAUDE.md` inaccuracy about which test pins the five header lengths. Note also that
  F13, F14, F18 and F19 are all shipped XML-doc defects that PHASE04's dimension would independently reach;
  PHASE05 should dedupe rather than let both phases report them.
- **PHASE05** — three severity questions PHASE02 declined to settle globally. (a) **F11 versus PHASE01's
  F04**: both are untranslated exceptions escaping the two container types, from adjacent code, and the
  broader fix closes both — they may be one finding with two symptoms. (b) **F12's severity turns on a
  judgement PHASE02 cannot make alone**: whether a third-party implementation is a real audience. §3.3 says
  "no external system ever unwraps these keys", but §1.1 says the spec exists so "a hand-written reader in
  another language" can get it right. Every verifier flagged the tension. (c) **F15 and F13 are the same
  fact from two sides** — the spec's "exactly two" count and the code doc's "only one" — and may merge.
- **R09 is worth keeping as a positive result**, not just an appendix entry: it is the first direct
  demonstration in this audit that §5's AAD binding is reachable rather than permanently masked by key
  confirmation.

**Documentation freshness sweep** — ran, and skipped by design. Under this item's code freeze its named
targets (`README.md`, `CLAUDE.md`, other prose docs) are exactly the files this item may not touch, and
PHASE04 is chartered to hunt staleness in them. What the sweep surfaced this phase — `CLAUDE.md`'s claim
about `FormatConstantsTests` — went into the report as **O08** and is forwarded to PHASE04, rather than
into an edit. The plan anticipates this explicitly.

**Line endings** — no CRLF/LF inconsistency was observed in any file read across the ten finder slices.
Recorded per the house rule that anything about line endings is an Observation and never a finding.

## Next

PHASE03 — test-suite quality & coverage gaps, on `feature/feature-f612-phase03-tests`. It is the first
phase that needs the **mutation carve-out** and the first to collect coverage, which it must measure **at
the audited commit** rather than reuse the plan's pre-dependency figures. It should read PHASE02's
*verified clean* list first — the offsets, the rejection matrix, the container-length arithmetic and the
fixture conformance are settled and need not be redone — and start from the four gaps forwarded above,
each of which already names the test that is missing and the defect it would have caught.
