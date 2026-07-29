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
| FEATURE-5A30 | True hybrid RSA + ML-KEM method `0x05`                     | DONE   | docs/plan/FEATURE-5A30.md |
| FEATURE-0D64 | Selectable RSA-OAEP hash for method `0x03`                 | DONE   | docs/plan/FEATURE-0D64.md |
| FEATURE-F612 | Full adversarial pre-release audit (report only)           | IN PROGRESS | docs/plan/FEATURE-F612.md |
| - PHASE01    | Cryptographic & security correctness                       | DONE   | (in FEATURE-F612.md)      |
| - PHASE02    | `docs/format.md` conformance                               | TODO   | (in FEATURE-F612.md)      |
| - PHASE03    | Test-suite quality & coverage gaps                         | TODO   | (in FEATURE-F612.md)      |
| - PHASE04    | Public API, documentation & packaging                      | TODO   | (in FEATURE-F612.md)      |
| - PHASE05    | Synthesis, severity calibration & triage handoff           | TODO   | (in FEATURE-F612.md)      |

## Notes on ordering

`FEATURE-67FD` → `FEATURE-00E7` → `FEATURE-11B6` → `FEATURE-07DA` is a hard sequence: there is
nothing to write types into before the solution exists, nothing to implement before the interfaces
and the format spec exist, and nothing valid to pack before the implementation is complete.

`FEATURE-5A30` was planned as deferred, became part of v1.0.0, and is now **`DONE`** — method `0x05` ships.
The pre-release sequence was `FEATURE-5A30` → `FEATURE-0D64` → `FEATURE-F612`; the first two are now
**`DONE`**, so **one item remains** before the release chain reaches its `CODE-REVIEW` step.

`FEATURE-0D64` followed `FEATURE-5A30` because the hybrid method extends the header reader/writer,
`FormatLayout`, `EncryptedDataHeader`, the RSA test helpers and the malformed-input sweep — the same files the
RSA-OAEP-hash item touches — so the reverse order would have meant two passes over each. That ordering paid
off as expected. Two predictions in the original note did **not** hold, and `docs/done/FEATURE-5A30.md`
records why: `DataEncryptionLimits` was left unchanged (the hybrid's two length fields are an RSA wrapped key
and an ML-KEM encapsulation, so the existing two caps already bound them — see `docs/format.md` §8), and
`EncryptedDataHeader` gained no new property, only new documentation, because both length properties already
existed. Neither item depended on the other technically; `0D64` changed only method `0x03` — but because it
ran second, it inherited the job of narrowing §4's fixed-parameter row, which by then covered the hybrid's
wrap too. It did narrow it: that row is now normative for method `0x05` alone, whose OAEP-SHA-256 wrap stays
fixed, and method `0x03` points at §3.3 instead. `docs/done/FEATURE-0D64.md` records the rest.

`FEATURE-F612` is last because it audits **the code that ships**: a method or a header field landing
after the audit is a construction nobody reviewed. Its own output is not the end of the sequence — the
report feeds an `/interview` run that mints a `CODE-REVIEW-HHHH` item (one severity-ordered phase per
finding), and **v1.0.0 is published only after that item's triage**. `FEATURE-07DA` prepared the release
and `docs/RELEASE.md` is the runbook; the maintainer runs it at the end of that chain, not before.

Both **format** items — `FEATURE-5A30` and `FEATURE-0D64` — were cheap because **v1.0.0 is prepared but not
published**, so no container existed outside this repository and the `0x05` and `0x03` header shapes could
change with no format-version bump. The entire cost was regenerating committed fixtures. Both spent that
window and both are now closed: `5A30` claimed the reserved `0x05` method byte and added a header shape and
three fixtures; `0D64` grew the `0x03` header by one byte at offset 5, moving every offset past 4 and
regenerating two fixtures plus two new ones. Format version stayed `0x10` throughout. **Publishing closes
the window** — a further header change would cost a version bump or a second method byte.
(`FEATURE-F612` has neither a header shape nor fixtures; what makes *its* timing matter is only that it must
audit the code that ships.)

`FEATURE-136E` was deferred on the same terms `FEATURE-5A30` originally was, and is now **`ABANDONED`**:
the migration need it existed
for never materialized, and its own plan said to mark it abandoned rather than delete it if that
happened. The row and the plan file stay for the record. Nothing supersedes it, and the door stays open
architecturally — `docs/format.md` still reserves format-version bytes `0x01`–`0x0F` for predecessor
files and the header reader still dispatches on the version byte — so a future item could add a legacy
reader as an addition rather than a redesign.
