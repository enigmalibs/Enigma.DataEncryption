# Enigma.DataEncryption — Roadmap

Single registry of all tracked work items. Details live in `docs/plan/<ID>.md`; completion records
in `docs/done/<ID>.md`. Row order is the work order (append new items last).

Status vocabulary: `TODO`, `IN PROGRESS`, `DONE`, `ABANDONED`.

| ID           | Title                                                      | Status | Plan                      |
|--------------|------------------------------------------------------------|--------|---------------------------|
| FEATURE-67FD | Repository & solution bootstrap                            | DONE   | docs/plan/FEATURE-67FD.md |
| FEATURE-00E7 | Binary format spec & public abstraction skeleton           | DONE   | docs/plan/FEATURE-00E7.md |
| FEATURE-11B6 | Core implementation                                        | DONE   | docs/plan/FEATURE-11B6.md |
| - PHASE01    | Shared format infrastructure                               | DONE   | (in FEATURE-11B6.md)      |
| - PHASE02    | Password-based services (PBKDF2 + Argon2)                  | DONE   | (in FEATURE-11B6.md)      |
| - PHASE03    | RSA service                                                | DONE   | (in FEATURE-11B6.md)      |
| - PHASE04    | ML-KEM service                                             | DONE   | (in FEATURE-11B6.md)      |
| - PHASE05    | Inspector, file extensions, DI & robustness suites          | DONE   | (in FEATURE-11B6.md)      |
| FEATURE-07DA | NuGet release preparation (v1.0.0)                         | DONE   | docs/plan/FEATURE-07DA.md |
| - PHASE01    | Package metadata & build config + license audit            | DONE   | (in FEATURE-07DA.md)      |
| - PHASE02    | Per-category guides & index                                | DONE   | (in FEATURE-07DA.md)      |
| - PHASE03    | README + release notes + community files                    | DONE   | (in FEATURE-07DA.md)      |
| - PHASE04    | Release runbook, pack-verify & final cut prep              | DONE   | (in FEATURE-07DA.md)      |
| FEATURE-136E | Legacy decrypt support for predecessor files               | ABANDONED — the predecessor-file migration need never materialized; no replacement item (format versions `0x01`–`0x0F` stay reserved) | docs/plan/FEATURE-136E.md |
| FEATURE-5A30 | True hybrid RSA + ML-KEM method `0x05`                     | TODO   | docs/plan/FEATURE-5A30.md |
| FEATURE-0D64 | Selectable RSA-OAEP hash for method `0x03`                 | TODO   | docs/plan/FEATURE-0D64.md |
| FEATURE-F612 | Full adversarial pre-release audit (report only)           | TODO   | docs/plan/FEATURE-F612.md |
| - PHASE01    | Cryptographic & security correctness                       | TODO   | (in FEATURE-F612.md)      |
| - PHASE02    | `docs/format.md` conformance                               | TODO   | (in FEATURE-F612.md)      |
| - PHASE03    | Test-suite quality & coverage gaps                         | TODO   | (in FEATURE-F612.md)      |
| - PHASE04    | Public API, documentation & packaging                      | TODO   | (in FEATURE-F612.md)      |
| - PHASE05    | Synthesis, severity calibration & triage handoff           | TODO   | (in FEATURE-F612.md)      |

## Notes on ordering

`FEATURE-67FD` → `FEATURE-00E7` → `FEATURE-11B6` → `FEATURE-07DA` is a hard sequence: there is
nothing to write types into before the solution exists, nothing to implement before the interfaces
and the format spec exist, and nothing valid to pack before the implementation is complete.

`FEATURE-5A30` was planned as deferred and **is now part of v1.0.0**: the release waits for it. The
three remaining items form the pre-release sequence `FEATURE-5A30` → `FEATURE-0D64` → `FEATURE-F612`,
and that order matters in both places it could be reversed.

`FEATURE-0D64` follows `FEATURE-5A30` because the hybrid method extends `EncryptedDataHeader`, the header
reader/writer, `FormatLayout`, the RSA test helpers and the malformed-input sweep — the same files the
RSA-OAEP-hash item touches — so the reverse order means two passes over each. (`DataEncryptionLimits` and
the inspector implementation are extended by `5A30` alone; `0D64` leaves both unchanged.) Neither item
depends on the other technically; `0D64` changes only method `0x03` — though because it runs second, it
inherits the job of narrowing §4's fixed-parameter row, which by then covers the hybrid's wrap too.

`FEATURE-F612` is last because it audits **the code that ships**: a method or a header field landing
after the audit is a construction nobody reviewed. Its own output is not the end of the sequence — the
report feeds an `/interview` run that mints a `CODE-REVIEW-HHHH` item (one severity-ordered phase per
finding), and **v1.0.0 is published only after that item's triage**. `FEATURE-07DA` prepared the release
and `docs/RELEASE.md` is the runbook; the maintainer runs it at the end of that chain, not before.

Both **format** items — `FEATURE-5A30` and `FEATURE-0D64` — are cheap now and expensive later for the same
reason: **v1.0.0 is prepared but not published**, so no container exists outside this repository and the
`0x05` and `0x03` header shapes can still change with no format-version bump. The entire cost is
regenerating committed fixtures. (`FEATURE-F612` has neither a header shape nor fixtures; what makes *its*
timing matter is only that it must audit the code that ships.)

`FEATURE-136E` was deferred on the same terms `FEATURE-5A30` originally was, and is now **`ABANDONED`**:
the migration need it existed
for never materialized, and its own plan said to mark it abandoned rather than delete it if that
happened. The row and the plan file stay for the record. Nothing supersedes it, and the door stays open
architecturally — `docs/format.md` still reserves format-version bytes `0x01`–`0x0F` for predecessor
files and the header reader still dispatches on the version byte — so a future item could add a legacy
reader as an addition rather than a redesign.
