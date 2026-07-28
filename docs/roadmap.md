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
| FEATURE-07DA | NuGet release preparation (v1.0.0)                         | IN PROGRESS | docs/plan/FEATURE-07DA.md |
| - PHASE01    | Package metadata & build config + license audit            | DONE   | (in FEATURE-07DA.md)      |
| - PHASE02    | Per-category guides & index                                | DONE   | (in FEATURE-07DA.md)      |
| - PHASE03    | README + release notes + community files                    | DONE   | (in FEATURE-07DA.md)      |
| - PHASE04    | Release runbook, pack-verify & final cut prep              | TODO   | (in FEATURE-07DA.md)      |
| FEATURE-136E | Legacy decrypt support for predecessor files (deferred)    | TODO   | docs/plan/FEATURE-136E.md |
| FEATURE-5A30 | True hybrid RSA + ML-KEM method `0x05` (deferred)          | TODO   | docs/plan/FEATURE-5A30.md |

## Notes on ordering

`FEATURE-67FD` → `FEATURE-00E7` → `FEATURE-11B6` → `FEATURE-07DA` is a hard sequence: there is
nothing to write types into before the solution exists, nothing to implement before the interfaces
and the format spec exist, and nothing valid to pack before the implementation is complete.

`FEATURE-136E` and `FEATURE-5A30` are **deferred by design** — they are recorded so the decisions
behind them are not lost, and are deliberately **not** part of the v1.0.0 release. Neither is
blocked by anything; both can be picked up at any time after `FEATURE-11B6`.
