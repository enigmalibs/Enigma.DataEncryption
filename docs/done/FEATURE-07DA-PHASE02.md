# FEATURE-07DA-PHASE02 — Per-category guides & index — DONE

**Branch:** `feature/feature-07da-phase02-guides`
**Plan:** `docs/plan/FEATURE-07DA.md` § PHASE02

## Summary

Added `docs/guides/` — six per-category usage guides plus the index — following the
`dotnet-release` `guide.md` / `guides-README.md` template shape (intro → supported operations table →
key types table → `###`-per-scenario usage → notes). One guide per category the library actually has;
no category was invented and none was merged.

The guides are **usage documentation only**. No product code changed, and no wire-format table was
copied out of `docs/format.md` — the index points at `../format.md` as the normative spec and frames
the split explicitly ("the guides above are *usage*; `format.md` is the *spec*").

Content decisions worth recording, because they are answers the public XML docs do not give in one
place:

- **Progress semantics.** `IProgress<int>` reports **increments** of payload bytes that sum to the
  payload length — not a running total and not a percentage. Verified against
  `DataEncryptionFileExtensionsTests.ProgressCountsPayloadBytesOnly`, which asserts on the *sum*. Every
  guide that shows progress accumulates the increments itself, so no snippet implies a cumulative
  counter.
- **The ML-KEM default-parameter-set trap.** This library's `EncryptAsync` defaults `parameterSet` to
  `MLKemParameterSet.MLKem1024`; Enigma.Core's `CreateMLKemService` defaults to `MLKem768`. Relying on
  both defaults at once generates a 768 key pair and encapsulates it as 1024, which throws
  `ArgumentException`. `ml-kem.md` calls this out in the supported-sets section and again in the notes,
  and every ML-KEM snippet names the parameter set on both sides.
- **The §9 error-mapping asymmetries are documented as deliberate**, not glossed. `rsa.md` distinguishes
  an unparseable PEM (propagates unwrapped as `ArgumentException` / `FormatException`) from a PEM that
  parses but does not open the container (`DataDecryptionException`, cause in `InnerException`).
  `ml-kem.md` documents the encrypt/decrypt asymmetry — `ArgumentException` on `publicKey` for
  `Encapsulate`, `DataDecryptionException` for every `Decapsulate` failure — and says why splitting
  them would require matching on message text.
- **ML-KEM key persistence.** The plan's documented pattern is implemented as two runnable snippets:
  write the public key raw, and protect the private key at rest by encrypting it with this library's own
  Argon2 service.
- **The file-extension semantics that are asserted, not incidental** — arguments validated before either
  file is opened, and the output handle closed before the cleanup delete — are stated in
  `file-operations.md` with the reasoning (`FileMode.Create` would truncate a caller's file; Windows
  cannot delete a file the process holds open).

## Files touched

**Created**

| Path | Lines | Covers |
|---|---|---|
| `docs/guides/README.md` | 59 | Index. Themed groups, all six guides, `../format.md` as the normative spec. |
| `docs/guides/password-based.md` | 333 | `IPbkdf2DataEncryptionService`, `IArgon2DataEncryptionService`; cost parameters and how to choose them; `byte[]` vs `char[]` passwords and clearing them; tightening `DataEncryptionLimits`. |
| `docs/guides/rsa.md` | 304 | `IRsaDataEncryptionService`; key generation via Enigma.Core's `IPublicKeyService`; PEM handling; encrypted private-key PEMs and `keyPassword`; the two distinct bad-key outcomes. |
| `docs/guides/ml-kem.md` | 378 | `IMLKemDataEncryptionService`; the three parameter sets with real sizes; key generation via `IMLKemService`; persisting raw `byte[]` keys; implicit rejection and the key-confirmation tag. |
| `docs/guides/header-inspection.md` | 336 | `IEncryptedDataInspector`, `EncryptedDataHeader`; detect-then-dispatch; cost gating; the seekable / non-seekable position behaviour. |
| `docs/guides/file-operations.md` | 377 | `DataEncryptionFileExtensions`: all twelve methods and the three documented semantics. |
| `docs/guides/dependency-injection.md` | 314 | `AddEnigmaDataEncryption()`: what it registers including the Enigma.Core factories, singleton lifetimes, `TryAdd` override behaviour, and manual registration for non-DI consumers. |
| `docs/done/FEATURE-07DA-PHASE02.md` | — | This record. |

**Modified**

| Path | Change |
|---|---|
| `docs/roadmap.md` | PHASE02 `TODO` → `IN PROGRESS` → `DONE`. |
| `docs/plan/FEATURE-07DA.md` | PHASE02 status flipped, and the completion-doc pointer added. |
| `CLAUDE.md` | Documentation-freshness sweep — three spots (see below). |

No file under `src/` or `tests/` was touched.

## Documentation freshness sweep

`CLAUDE.md` was the only stale prose this dev produced; `README.md` and `RELEASENOTES.md` are still
0-byte placeholders that PHASE03 owns, and there is no `CHANGELOG.md` or `CONTRIBUTING.md` by design.
All three spots were refreshed, with the maintainer's approval, into this dev's own commit:

- **Project layout tree** — added `docs/guides/`, noting it is repo-only and not packed.
- **Conventions → Documentation** — was future tense ("guides *will* live under `docs/guides/`"). Now
  describes what exists, and records the two constraints a later dev could otherwise break: the guides
  are never packed so their relative links (including `../format.md`) must stay relative, and the packed
  root README must therefore point at them in prose with no clickable `docs/…` link. Also records that
  the snippet gate is a per-dev obligation rather than a build step, since there is no permanent
  doc-sample test project.
- **Dev workflow → dependency chain** — `PHASE01 done, PHASE02 next` → `PHASE01–02 done, PHASE03 next`.

## The snippet-verification gate

The plan calls this gate "the only thing that catches drift", so it was run **mechanically rather than
by inspection**: a throwaway compile harness was generated in the session scratchpad (never in the
repo), one `net10.0` project per snippet, each `ProjectReference`-ing the real
`Enigma.DataEncryption.csproj` and `PackageReference`-ing `Microsoft.Extensions.DependencyInjection`
9.0.18, with `Nullable=enable` and `ImplicitUsings=disable` so each snippet's own `using` block has to
be complete. Every snippet was compiled; the harness was then deleted.

Fences split into two kinds:

- **41 sample fences** — complete, copy-pasteable programs. All 41 compile. Two related fences in
  `dependency-injection.md` (the `DocumentVault` type and its registration) were compiled together as
  one unit, since the second references the first.
- **7 signature fences** — API declaration listings, not programs. Each block was matched
  whitespace-normalised against the real declaration in `src/`; all 10 blocks (some fences list two
  methods) matched their source declaration exactly, modulo the trailing `;` of the declaration form.

Enigma.Core symbols were verified the same way — the compile harness resolves them against the real
`Enigma.Core` 1.0.0 assembly, so `IPublicKeyService.GenerateRsaKeyPair`, `IMLKemService.GenerateKeyPair`,
`CreateMLKemService`, `CreatePublicKeyService` and `MLKemParameterSet` are confirmed against the
shipping API, not against memory. The ML-KEM size table (public 800/1,184/1,568 B, private
1,632/2,400/3,168 B, encapsulation 768/1,088/1,568 B) was produced by **running** Enigma.Core's
`GenerateKeyPair`/`Encapsulate` for all three parameter sets rather than quoting FIPS 203 from memory;
the encapsulation column agrees with `docs/format.md` §3.4.

### Coverage

| Guide | Snippets (compiled / signature) | Library symbols | Enigma.Core symbols | Mismatches | Uncertain |
|---|---|---|---|---|---|
| `password-based.md` | 8 (6 / 2) | 19 | 0 | 0 | 0 |
| `rsa.md` | 7 (6 / 1) | 10 | 4 | 0 | 0 |
| `ml-kem.md` | 9 (8 / 1) | 13 | 6 | 0 | 0 |
| `header-inspection.md` | 7 (6 / 1) | 29 | 0 | 0 | 0 |
| `file-operations.md` | 8 (7 / 1) | 22 | 1 | 0 | 0 |
| `dependency-injection.md` | 9 (8 / 1) | 19 | 8 | 0 | 0 |
| **Total** | **48 (41 / 7)** | **45 distinct** | **16 distinct** | **0** | **0** |

Symbol counts are per-guide distinct identifiers resolved by reflection against the exported surfaces of
`Enigma.DataEncryption.dll` and `Enigma.Core.dll` (string-literal text and compiler-generated record
members excluded). **One mismatch was found and fixed**, which is the gate justifying itself: the last
`dependency-injection.md` snippet used `MLKemServiceFactory` without `using Enigma.Core.Asymmetric.Pqc;`
— `error CS0246`. It would have been invisible to a careful read.

Eleven exported symbols appear in prose or a table but in no snippet: `Twofish256Gcm`,
`Camellia256Gcm`, `DataEncryptionException`, `DataEncryptionFileExtensions`, `ServiceCollectionExtensions`,
`DataEncryptionLimits.Default`, and the five fixed-size constants (`DataKeySizeBytes`, `NonceSizeBytes`,
`SaltSizeBytes`, `GcmMacSizeBits`, `KeyConfirmationTagSizeBytes`). That is intentional — `Cipher` values
are covered by the enum's own table, the two static classes are never named by callers (their members
appear as extension methods and as `AddEnigmaDataEncryption()`), and the constants are format invariants
a caller reads rather than passes.

### Link check

All seven distinct relative links across the guides resolve (`../format.md` plus the six sibling
guides). There are no absolute GitHub URLs and no external links. `grep` confirms no wire-format offset
table was duplicated into any guide.

## Deviations & follow-ups

- **Sub-agent delegation was not used.** The plan suggested one sub-agent per guide. This session runs
  under an explicit instruction not to invoke the Agent tool unless the user asks for it, so the six
  guides were authored in a single context. Delegation is not one of PHASE02's acceptance criteria, and
  authoring in one context arguably served the snippet gate better: the whole public surface of both
  assemblies was already loaded, and the six guides cross-link consistently. No acceptance criterion was
  affected.
- **The compile harness is not a permanent artifact.** The plan notes a doc-sample test project as the
  known alternative and does not require it; Enigma.Core considered and declined it. The harness built
  here was scratch — regenerating it is a few minutes' work if PHASE03's README quick-start needs the
  same gate (acceptance criterion 7 of PHASE03), and the generator approach is described above precisely
  so it can be repeated.
- **`ml-kem.md` and `header-inspection.md` reference a raw private-key file** (`recipient.mlkem.key.raw`)
  in two snippets, alongside the encrypted-at-rest pattern the same guide recommends. The two coexist on
  purpose — the failure-mode and limits snippets need a one-line key load, and the persistence section is
  where the recommended handling lives.
- **Line endings:** all new files are LF, matching the existing `docs/*.md`. No CRLF inconsistency was
  observed; nothing to normalise.
- **Follow-up for PHASE03 (not a defect):** the README's *Documentation* section must describe the guides
  **in prose without clickable per-guide links**, because the README is packed and renders on nuget.org
  where `docs/` does not exist. The guides themselves are repo-only, so their relative links are correct
  as written and must not be "fixed" to absolute URLs.

## Build/test evidence

```
dotnet build Enigma.DataEncryption.slnx -c Release
  Build succeeded.
      0 Warning(s)
      0 Error(s)

dotnet test --solution Enigma.DataEncryption.slnx -c Release
  Test run summary: Passed!
    net8.0|x64  passed
    net10.0|x64 passed
    total: 16162   failed: 0   succeeded: 16162   skipped: 0
```

No test was added or changed: this phase ships documentation only, and the acceptance criteria that
would normally be covered by tests — every snippet resolving against the real API — were verified by
the compile harness described above. The suite is re-run to confirm the phase changed nothing.

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | Six guides plus the index exist, following the template shape | ✅ `docs/guides/` — six category guides + `README.md`, each with intro → operations table → key types → `###`-per-scenario usage → notes |
| 2 | The index links `../format.md` as the normative spec; no format tables duplicated | ✅ Index § *The binary format*; `grep` confirms no offset table in any guide |
| 3 | Snippet-verification gate run; coverage table recorded; **zero** mismatches remaining | ✅ 48 fences verified (41 compiled, 7 matched against source); 1 mismatch found and fixed, 0 remaining |
| 4 | Every guide's snippets verified against both this library's and Enigma.Core's real public surface | ✅ The harness resolves both assemblies; ML-KEM sizes measured by running Enigma.Core |
| 5 | Zero-warning Release build; full suite still green | ✅ 0 warnings; 16,162 / 16,162 passing over both test TFMs |
