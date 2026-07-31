# FEATURE-11B6-PHASE05 — Inspector, file extensions, DI & robustness suites

**Status:** DONE
**Branch:** `feature/feature-11b6-phase05-integration`

## Summary

The last two unimplemented bodies in the library are gone, and the cross-cutting suites that needed all
four methods present now exist. `FEATURE-11B6` is complete: **no `NotImplementedException` remains
anywhere in `src/`.**

**`EncryptedDataInspector.ReadHeaderAsync`** parses a header through PHASE01's `HeaderReader` with no
expected method — the inspector reads all four — and returns only `ParsedHeader.Header`, so the salt,
nonce, wrapped key, encapsulation and confirmation tag stay on the internal type and the public record
keeps carrying no secret. The stream position is captured *before* the parse and restored in a `finally`,
which matters most on the failure path: a caller probing a file it is unsure about gets its stream back
untouched rather than half-consumed.

**The twelve `DataEncryptionFileExtensions` methods** open both files with the documented modes, delegate
to the stream overload, and delete the output on any failure. Two details carry the weight. First, the
output handle lives in a nested scope *inside* the `try`, so it is flushed and closed before the `catch`
runs — deleting a file this process still holds open fails on Windows, so the ordering is what makes the
cleanup work rather than merely be attempted. Second, a failure opening the *input* happens outside the
`try`, where there is no output file yet, so an unrelated file sitting at `outputPath` is never touched.

**`AddEnigmaDataEncryption()` needed no code change** — it has been real since FEATURE-00E7 — so its share
of this phase was test work: proving that a pre-registered factory is what the *resolved services* are
built against (not merely what stays in the collection), and that all five resolved instances round-trip a
payload through the composition a consumer actually gets.

Four new cross-cutting suites, all generated rather than hand-written:

- **`MalformedContainerSweepTests`** — ~2,600 corrupted or truncated containers per TFM, driven through all
  four services. It asserts the *admissible set* (`DataEncryptionFormatException` or
  `DataDecryptionException`) rather than which of the two, because for several cases the answer is a
  documented judgement call (§9) and the per-method suites already pin those individually. What this suite
  is for is the outcome nobody wants: an `IndexOutOfRangeException` from a hand-rolled offset, an
  `OutOfMemoryException` from trusting a length field, or an unwrapped Enigma.Core exception.
- **`ServiceThreadSafetyTests`** — one instance of each of the five services driven from 32 tasks on
  *distinct* payloads and ciphers, plus a mixed success/failure run and an all-five-at-once run. Distinct
  inputs are the point: concurrent work on identical inputs can pass while state is shared.
- **`EncryptedDataInspectorTests`** — field reporting per shape, the seekable/non-seekable position
  contract in both directions and on both the success and failure paths, and a generated malformed-input
  sweep admitting `DataEncryptionFormatException` *only* (the inspector has no credential, so
  `DataDecryptionException` is unreachable for it).
- **`GoldenVectorInventoryTests`** — the executable inventory of all twenty committed fixtures. It agrees
  with the directory in both directions, so a fixture added without a row or a row left behind after a
  deletion fails here, and every container row decrypts with the credential it names.

## Files/modules touched

**Created (library):** none — both implementations replaced existing `NotImplementedException` bodies.

**Modified (library):**

- `src/Enigma.DataEncryption/Services/EncryptedDataInspector.cs` — implemented `ReadHeaderAsync`.
- `src/Enigma.DataEncryption/DataEncryptionFileExtensions.cs` — implemented all twelve methods, plus the
  shared `RunAsync` / `TryDelete` / validation helpers. Added the missing
  `<exception cref="ArgumentOutOfRangeException">` entries on the four password-encrypt wrappers (see
  *Deviations*).

**Created (tests):**

- `Services/ContainerMethodKind.cs`, `Services/ContainerMethodHarness.cs` — one uniform surface over all
  four methods (streams, file paths, a wrong credential), which is what lets the cross-cutting suites be
  written once and generated over every method.
- `Services/TempWorkspace.cs` — a per-test temp directory.
- `Services/EncryptedDataInspectorTests.cs`
- `Services/DataEncryptionFileExtensionsTests.cs`
- `Services/MalformedContainerSweepTests.cs`
- `Services/ServiceThreadSafetyTests.cs`
- `Services/GoldenVectorInventoryTests.cs`

**Modified (tests / config):**

- `DependencyInjection/ServiceCollectionExtensionsTests.cs` — removed the stale "behaviour is still
  `NotImplementedException`" class comment; added the resolved-service round-trip, the file-extension
  composition test, and the `TryAdd`-reaches-the-services test.
- `Internal/LimitsValidatorTests.cs` — each Argon2 cap tightenable independently (also the last uncovered
  lines in `DataEncryptionLimits`).
- `Enigma.DataEncryption.UnitTests.csproj`, `Directory.Packages.props` — added
  `Microsoft.Testing.Extensions.CodeCoverage` 18.0.4 (test-only, `PrivateAssets=all`); see *Deviations*.

**Modified (docs):**

- `docs/format.md` — §9 now states that a header-only reader raises the format half of the mapping alone.
- `docs/roadmap.md`, `docs/plan/FEATURE-11B6.md` — PHASE05 and the parent item to `DONE`.
- `CLAUDE.md` — from the documentation freshness sweep: the "Current state" section rewritten for a finished
  implementation (it still claimed the inspector and the file-path extensions threw
  `NotImplementedException`, and named PHASE05 as next), and the dependency-chain line now points at
  `FEATURE-07DA`.

## Deviations & follow-ups

**1. Coverage could not be collected with `coverlet.collector`, as the plan assumed.** `coverlet.collector`
is a VSTest data collector and registers no extension with the Microsoft Testing Platform runner this repo
pins — the built test host exposes no coverage option at all. Resolved (with the maintainer's agreement) by
adding `Microsoft.Testing.Extensions.CodeCoverage`, the MTP-native equivalent, as a second test-only
`PrivateAssets=all` reference. `coverlet.collector` is kept for a VSTest-based IDE runner, and both
`Directory.Packages.props` and the csproj now say which one actually produces a figure. Collected with:

```bash
dotnet test --solution Enigma.DataEncryption.slnx -c Release -- --coverage --coverage-output-format cobertura
```

**2. The file wrappers validate arguments before opening either file, which the plan did not specify.** The
thin alternative — forward everything and let the service validate — has a real defect: the output is opened
`FileMode.Create`, so an empty password would truncate the caller's existing file *and then delete it*
before the credential was ever looked at. The wrappers therefore re-check what they can (`service`, both
paths, the cipher, the credential's null/emptiness, and the KDF cost bounds) using the same internal
validators the services use where those exist. The cipher, password and ML-KEM parameter-set checks are the
services' own code; the PEM-emptiness, KEM-key-emptiness and cost-bound checks are two-line duplicates,
which is the cost of the guarantee. `AnEmptyCredentialIsRejectedWithoutTouchingEitherFile` pins it.

**3. Two XML-doc omissions in FEATURE-00E7's file-extension surface were corrected.** The four password
`EncryptFileAsync` wrappers documented `ArgumentException` but not `ArgumentOutOfRangeException`, which the
underlying services throw for a non-positive cost parameter and which the wrappers now throw directly. No
signature changed.

**4. `docs/format.md` needed no drift correction.** Re-verified §1.1 (LE `Int32`), §2–§3.4 (every offset and
header length), §4/§4.1 (all ten fixed parameters and four defaults against `DataEncryptionDefaults`), §5,
§6, §7, §8 (all six caps against `DataEncryptionLimits`) and §9 (every row, including the RSA
"unwraps to a length other than 32 bytes" rule, which `RsaDataEncryptionService.UnwrapDataKey` does
enforce). The one edit is an addition rather than a fix: §9 said nothing about a header-only reader, which
now exists.

**5. The malformed-input sweep deliberately does not repeat the per-method bit-flip sweeps.** PHASE02–PHASE04
each flip a bit in every header field of their own method; re-running that across four methods would have
added ~1,200 KDF/unwrap operations to assert something already asserted. The sweep covers what the plan
lists — byte and `Int32` field edits, every header truncation offset, payload truncations, and degenerate
streams — plus all-zero, all-`0xFF` and forged-prefix buffers.

**6. `TeeStream`'s unused `Stream` members stay uncovered, by necessity.** It is private inside
`HeaderReader`, and Enigma.Core's stream helpers only ever call the `byte[]` read overloads, so the
`Span`/`Memory` overloads and the `NotSupportedException` guards are unreachable from a test. They exist to
satisfy the `Stream` contract. Likewise the `IOException` arm of `TryDelete` (a blocked delete surfaces as
`UnauthorizedAccessException`, which *is* covered), the documented-unreachable default arm of
`HeaderReader`'s method switch, and two compiler-generated record lines.

**7. `ADeleteFailureDoesNotMaskTheOriginalException` runs on Unix only.** Forcing a delete to fail means
removing write permission from the containing directory, which only Unix file modes let a test do reliably;
on Windows it calls `Assert.Skip`. A Windows equivalent would need a second process and would prove the same
thing.

**8. Line endings.** No CRLF/LF inconsistency observed in any touched file; no action taken (recommendation
only, per the workflow).

## Build/test evidence

- **Build:** `dotnet build Enigma.DataEncryption.slnx -c Release` — **succeeded, 0 warnings** (all three
  library TFMs plus both test TFMs, with `TreatWarningsAsErrors` and `EnforceCodeStyleInBuild`).
- **Tests:** `dotnet test --solution Enigma.DataEncryption.slnx -c Release` — **16,162 passed, 0 failed,
  0 skipped** across `net8.0` and `net10.0` (up from 6,636 at the start of this phase). Wall clock ~19 s.
- **`NotImplementedException`:** `grep -rn "NotImplementedException" src/ --include=*.cs` returns nothing.
- **Coverage** (`Enigma.DataEncryption` only; the run also instruments Enigma.Core, which dilutes the
  solution-level number to 53.42%):

  | TFM | Line | Branch |
  |---|---|---|
  | net8.0 | **97.43%** | **90.82%** |
  | net10.0 | **97.43%** | **90.82%** |

  The residual is enumerated in *Deviations* item 6.
- **Guards still green:** `BouncyCastleIsolationTests`, `InternalSurfaceIsolationTests` and
  `FormatConstantsTests` all pass — the new `Internal/`-facing test harness added no exported type and no
  BouncyCastle leak.

## Acceptance criteria

| # | Criterion | Met |
|---|---|---|
| 1 | Inspector implemented, seekable-restore asserted both ways | ✔ — plus restore-on-failure and the non-seekable left-at-payload case |
| 2 | File extensions implemented, all three semantics asserted, no orphaned output after failure | ✔ — wrong credential, tampered payload, non-container input and cancellation, per method |
| 3 | `AddEnigmaDataEncryption()` wired; singleton identity and `TryAdd*` survival asserted | ✔ — and `TryAdd*` survival proven to reach the resolved services |
| 4 | Malformed-input sweep is a generated matrix over every field and every truncation offset, all four shapes | ✔ |
| 5 | Thread-safety suite passes for all five services | ✔ |
| 6 | No `NotImplementedException` anywhere in the library | ✔ |
| 7 | `BouncyCastleIsolationTests` passes | ✔ |
| 8 | `docs/format.md` re-verified; drift corrected | ✔ — no drift found; §9 gained a header-only-reader note |
| 9 | Coverage figure recorded | ✔ — 97.43% line / 90.82% branch (see *Deviations* item 1 for the tooling change) |
| 10 | Zero-warning Release build; suite green on both test TFMs | ✔ |
