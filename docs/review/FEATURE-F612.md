# Code Review — Enigma.DataEncryption (pre-v1.0.0)

**Date:** 2026-07-29
**Commit reviewed:** `b1ab2c2918cb569fcec1de9ef7bdce92b7039972` (branch `develop`, at the merge of
`feature/feature-0d64-rsa-oaep-hash`)
**Work item:** `FEATURE-F612` — full adversarial pre-release audit, report only. See
`docs/plan/FEATURE-F612.md`.
**Status:** PHASE01 and PHASE02 complete. PHASE03–PHASE04 append their dimensions below; PHASE05 writes
the executive summary and the release gate, deduplicates across dimensions and recalibrates severity
globally.

**Running total: 19 findings — 2 Medium and 7 Low from PHASE02 (F11–F19), on top of PHASE01's 3 Medium
and 7 Low (F01–F10). No Critical and no High has survived refutation in either phase.** Twelve
Observations (O01–O12) and fourteen refuted candidates (R01–R14) are recorded in the appendices. Each
phase's section carries its own Findings / Observations / Considered-and-refuted / Coverage blocks;
PHASE05 merges them.

## Scope

One dimension per phase. This revision contains **PHASE01 — cryptographic & security correctness**
only, over `src/Enigma.DataEncryption/Services/`, `src/Enigma.DataEncryption/Internal/`,
`Exceptions/`, `DataEncryptionDefaults.cs` and `DataEncryptionLimits.cs`, checked against **RFC 8017**
(RSAES-OAEP), **RFC 8018** (PBKDF2), **RFC 9106** (Argon2id), **FIPS 203** (ML-KEM) and **NIST
SP 800-38D** (GCM), and against `docs/format.md` as the normative contract.

`DataEncryptionFileExtensions.cs` is not in PHASE01's slice but produced one admitted finding (F03)
while the file-handle and cleanup ordering was being read as supporting evidence; PHASE05 may re-home
it.

## Method

Per `docs/plan/FEATURE-F612.md` §*Method*: fan-out, then adversarial refutation.

1. **Find.** Eight dimension-specific finder sub-agents, each with fresh context over a defined slice:
   key-material lifetime · randomness and nonce uniqueness · constant-time comparison and key
   confirmation · AEAD binding and GCM parameters · exception translation against §9 · ordering
   invariants and the async contract · the hybrid combiner, ML-KEM implicit rejection and the threat
   model · default cost parameters and the limits as a DoS bound. Every finder was primed with the
   eleven deliberate choices this repository documents, and told that a candidate contradicting one
   must argue against its stated reasoning rather than restate the observation. **32 candidates.**
2. **Deduplicate.** 32 candidates → **20 distinct claims** (five finders independently raised F04, four
   raised F01, three raised F05).
3. **Refute.** Each of the 20 was handed to **three independent verifier sub-agents with distinct
   lenses** — *correctness*, *security*, *reproducibility* — each instructed to **default to refuted
   when uncertain**. **60 verifiers.**
4. **Admit.** A candidate enters the Findings section only on surviving **at least 2 of 3** refutation
   attempts. **10 admitted, 10 refuted.**

Verifiers reproduced independently rather than trusting the finder's evidence, and several corrected it;
every correction that changed a mechanism, a threshold or a citation is recorded with its finding. The
severity on each finding is the **median of its three verifiers' independent severity opinions**, not
the finder's proposal — that recalibration alone moved three candidates down from High.

**Severity scale.** `Critical` / `High` / `Medium` / `Low` are actionable and map 1:1 onto phases of the
`CODE-REVIEW` item this report mints. **Observations** are informational and do **not** become phases.
The boundary: if you would not open a branch for it, it is an Observation. Anything about line endings is
an Observation by house rule.

## Build & test baseline (acceptance criterion 7)

Measured at the audited commit, before any analysis:

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

Both test TFMs (`net8.0`, `net10.0`). **The audited commit builds warning-free and the whole suite
passes.** Every finding below is therefore a defect the green suite does not detect, and each records why.

## Executive summary

*(PHASE05.)*

## Release gate

*(PHASE05 — which findings, if any, must block v1.0.0.)*

---

# Findings

No `Critical` and no `High` finding survived refutation. Three `Medium`, seven `Low`.

Ordered Critical → High → Medium → Low. Each carries a severity, a `file:line`, a concrete failure
scenario, a recommended fix, and a refutation record listing all three verifiers' lens, verdict and
one-line reasoning, followed by the strongest surviving counter-argument.

---

## Medium

### F01 — Streaming decryption releases the whole payload as unverified, attacker-bit-flippable plaintext before the GCM tag is checked, and nothing says so

**Severity:** Medium (verifier opinions: Medium / Low / Medium) · **Candidate:** C02 · raised
independently by 4 of 8 finders
**Location:** `src/Enigma.DataEncryption/Internal/PayloadCipher.cs:81-112` (all five callers);
`docs/format.md:519-520` (§7.2 step 6); the `<remarks>` on all **seven** stream `DecryptAsync`
overloads across the five service interfaces

**What is wrong.** `PayloadCipher.DecryptAsync` delegates to Enigma.Core's
`IBlockCipherService.DecryptAsync` and translates the trailing `CryptographicException` into
`DataDecryptionException`. Enigma.Core loops `cipherStream.ReadAsync(buffer, 0, 4096)` →
`output.WriteAsync(...)`, and BouncyCastle's `CipherStream` only reaches `DoFinal` — the MAC check —
when the input hits EOF. So every 4,096-byte chunk of plaintext is written to the caller's output stream
before authentication can fail. GCM is CTR-based, so an attacker flipping ciphertext bits chooses
exactly which plaintext bits change.

The library knows the behaviour exists: `DataEncryptionFileExtensions` deletes the partial output and
`docs/guides/file-operations.md:55-56` says "A failed decrypt therefore never leaves a truncated
plaintext on disk" — a sentence that only makes sense because the stream path does. But **the word
*unauthenticated*, and its consequence, appear nowhere.** The guides warn that the output stream keeps
partial output **on cancellation** (`docs/guides/password-based.md:308-310`) and never that it keeps
attacker-influenced plaintext **on authentication failure**.

**Failure scenario.** `await pbkdf2.DecryptAsync(containerFileStream, networkStream, password)` for a
1 MiB container; an attacker flips one ciphertext bit. Reproduced: all **1,048,576** bytes reach the
caller's output stream, in 256 separate `WriteAsync` calls, with exactly the attacker's chosen byte
altered, before `DataDecryptionException` is thrown. Threshold measured exactly —
`floor(size / 4096) * 4096` bytes released, so ≤ 4,095-byte payloads release nothing and everything
larger releases effectively all of it.

Why the green suite misses it: the tamper tests use `Plaintext(256)`
(`PasswordFailureTests.AFlippedPayloadBitIsADecryptionError`) and `Plaintext(200)`
(`AFlippedBitAnywhereInThePayloadIsADecryptionError`), both below 4,096, and neither inspects
`output.Length`. All nine `Assert.Equal(0, output.Length)` assertions in the failure suites sit on
**wrong-credential** paths, which genuinely release nothing.

**Recommended fix.** Do not change the streaming behaviour — buffering a whole payload to authenticate
first would defeat the API. Make the property normative and visible: state in `docs/format.md` §7.2
step 6 that a failed decrypt may leave up to `payloadLength − 16` bytes of **unauthenticated** plaintext
in `output`, that the caller must treat `output` as untrusted until the returned task completes
successfully, and point callers at the file-path wrappers or their own discard-on-failure sink. Add the
same sentence to the `<remarks>` of all seven stream `DecryptAsync` overloads. Add one test per method
asserting that a tampered >4 KiB payload **does** leave bytes in `output`, so the behaviour is pinned
rather than incidental.

**Corrections applied during refutation.**
- **§5 is not contradicted and must not be cited as over-promising.** Two verifiers independently
  confirmed that an edited *header* byte is caught by `kcTag` at §7.2 step 5 and releases **0 bytes**,
  even for a 1 MiB payload, because any header edit changes `K` and therefore `kcKey`. The gap is
  confined to **payload-ciphertext** tampering. The doc fix belongs at §7.2 step 6 and in the XML
  remarks, not in §5.
- Seven stream `DecryptAsync` overloads, not six.
- The library never calls `FlushAsync`; one verifier's recording sink logged 256 writes and 0 flushes.
  The writes alone are what reach an unbuffered `NetworkStream`.
- The finder's claim to have *decompiled* `BlockCipherService` rested on a failed `ilspycmd`
  invocation. The 4,096-byte chunking is established **behaviourally**, so a regression test should
  assert "a large tampered payload releases bytes" rather than pin the exact multiple.

**Refutation record.**
- **correctness — not refuted:** "Independently reproduced with my own harness: a tampered 1 MiB
  container hands all 1,048,576 plaintext bytes to the caller's output stream in 256 separate writes —
  with exactly the attacker's chosen byte altered — before `DataDecryptionException` is thrown, and
  neither `docs/format.md` §7.2 step 6 nor the `<remarks>` on any of the six stream `DecryptAsync`
  overloads says so, while the only disclosure in the repo (the file wrappers' delete-on-failure) covers
  the path that is already mitigated."
- **security — not refuted:** "Granting the repro, the impact is narrow and conditional — the attacker
  must already be able to modify the container, and the caller must act on the output stream before
  awaiting the returned task — but the escalation from attacker-chosen truncation to attacker-chosen
  bit-flips in already-delivered plaintext is a real loss of the integrity property GCM is there to
  provide, and a spec that calls itself the contract and spends a page arguing why publishing `kcTag`
  is *not* a weakening should not leave release-of-unverified-plaintext entirely unstated; it stands as
  a documentation item, not at High."
- **reproducibility — not refuted:** "I reproduced this independently against the Release assembly and
  every number holds — a 1 MiB payload with one flipped ciphertext bit puts all 1,048,576 plaintext
  bytes on the caller's output stream in 256 separate `WriteAsync` calls before
  `DataDecryptionException`, with exactly one byte differing by the attacker's chosen XOR of `0x80`,
  while a wrong password still releases 0 bytes; the threshold is `floor(size/4096)*4096`, no test in
  the suite covers it, and neither `docs/format.md` nor any XML doc warns a stream caller that `output`
  is unauthenticated until the task completes."

**Strongest surviving counter-argument.** Release of unverified plaintext is inescapable for a
single-pass streaming AEAD — .NET's own `CryptoStream` and BouncyCastle's `CipherStream` behave
identically, the finding itself forbids changing it, and the returned `Task` *is* the authentication
verdict, so a caller who acts on `output` before awaiting it has committed an ordinary async error
rather than been misled. The repository also discloses the property obliquely twice, at
`docs/guides/file-operations.md:55-56` and at §6.3 ("a wrong ML-KEM key would surface as a GCM
authentication failure only after streaming the entire payload"). It survives because both disclosures
frame partial output as a *tidiness* problem — a "truncated plaintext" to be deleted — and never as an
*integrity* problem, and because the one word that would change a caller's design, *unauthenticated*,
is absent from the entire repository.

---

### F02 — Every nonce, salt and RSA data key comes from a per-thread userland DRBG that is OS-seeded once and never reseeded, so duplicated process state repeats the byte sequence

**Severity:** Medium (verifier opinions: Medium / Medium / Medium — unanimous) · **Candidate:** C07
**Location:** `src/Enigma.DataEncryption/Internal/RandomSource.cs:12`; call sites
`Pbkdf2DataEncryptionService.cs:155-156`, `Argon2DataEncryptionService.cs:160-161`,
`RsaDataEncryptionService.cs:126` and `:133`, `HybridDataEncryptionService.cs:166` and `:175`

**What is wrong.** `RandomSource` delegates to Enigma.Core's `RandomUtils.GenerateRandomBytes`, which is
a `[ThreadStatic] new SecureRandom()` — byte-identical on all three TFMs. In BouncyCastle 2.6.2 that
parameterless constructor is `CreatePrng("SHA256", autoSeed: true)`: a `DigestRandomGenerator`
auto-seeded **once** from `SecureRandom.MasterRandom` (the only OS-backed generator) and thereafter a
closed chain, `state = SHA256(LE64(ctr++) ‖ state ‖ seed)`, that never consults the OS again. Two
consequences:

- **(a)** Any duplication of process state re-runs the identical output sequence. For methods `0x01`
  and `0x02` the salt **and** the nonce repeat, so with a reused password `K` repeats too; for `0x03`
  the data key **and** the nonce repeat. That is GCM (key, nonce) reuse, which SP 800-38D §8 forbids
  absolutely.
- **(b)** The surviving generator state is a long-lived in-heap secret that predicts every **future**
  nonce, salt and RSA data key on that thread, and is never cleared — in a library otherwise fastidious
  about exactly this (`CryptoHelpers.Clear` in every `finally`, `KeyMaterialClearingTests`).

Methods `0x04` and `0x05` escape the *key* half: BouncyCastle's `MLKemEncapsulator` calls
`CryptoServicesRegistrar.GetSecureRandom()`, which builds a fresh OS-seeded `SecureRandom` per
encapsulation, so `kemSecret` differs even when the nonce repeats.

**Failure scenario.** Deploy on a platform that checkpoints and restores or clones **live process**
state — CRIU, Firecracker, AWS Lambda SnapStart for .NET (GA Nov 2024), live-VM snapshot-and-clone. The
snapshot captures a thread whose generator has already been used, and two restored instances each
encrypt under the same password: both emit the same 16-byte salt and the same 12-byte nonce, so both
derive the same `K` and encrypt different plaintexts under the same (K, nonce). An attacker holding both
containers recovers `P1 ⊕ P2` and the GHASH subkey `H` from the two tags, yielding arbitrary forgeries
under that key. Method `0x03` is worse, since the repeated 32-byte data key is itself the whole secret.

**This was demonstrated, not merely argued.** The reproducibility verifier confirmed at runtime that the
thread-static generator is a SHA-256 `DigestRandomGenerator` (byte-identical over 200 draws spanning 20
seed cycles), then restored its fields to a captured snapshot and made the library emit a
**byte-identical 53-byte PBKDF2 header** — same nonce, same salt, same `kcTag` — with
`C1 ⊕ C2 == P1 ⊕ P2`, recovering the second plaintext from the first. The no-restore control differed.

**Recommended fix.** Make `RandomSource` use the platform CSPRNG directly instead of `RandomUtils`:
`#if NETSTANDARD2_0` a static `RandomNumberGenerator.Create()` with `GetBytes(buffer)`, `#else`
`RandomNumberGenerator.Fill(buffer)`. Available on every target framework, adds no dependency, touches
no public surface, leaks no BouncyCastle type (the isolation invariant is untouched), keeps the
`IRandomSource` seam internal, and removes the only long-lived RNG secret in the process. One line of
this library's code.

**Corrections applied during refutation.**
- The predictive state is **not** "the 32-byte seed": `AutoSeed` feeds 2 × 32 bytes plus a counter
  through `AddSeedMaterial`, and what survives is the pair (`state`, `seed`) — 64 bytes plus
  `stateCounter`/`seedCounter`.
- **"Not the platform CSPRNG" must not be read as "predictable".** 64 bytes of OS seed chained through
  SHA-256 is a sound DRBG; nothing is predictable absent state duplication. Consequence (b) is
  defence-in-depth.
- "A container/VM **image** captured after warm-up" is wrong — an image carries filesystem, not process
  state. Only live process/VM checkpoint-restore qualifies.
- Lambda SnapStart snapshots after the *Init* phase, so it captures the generator only if a warm-up
  encryption runs during initialization — which AWS's own priming guidance encourages, so it is a real
  pattern rather than a stretch. CRIU and live-VM cloning need no such caveat.
- `RandomNumberGenerator.Fill` is **not** an unconditional cure: on a whole-VM clone whose kernel CSPRNG
  state is duplicated too, it repeats as well. Its value is against *process*-level checkpoint-restore
  and on vmgenid-equipped platforms, and the fix should say so.

**Refutation record.**
- **correctness — not refuted:** "I decompiled the shipped assemblies and every link holds:
  `RandomSource.cs:12` calls `RandomUtils.GenerateRandomBytes`, which is a `[ThreadStatic] new
  SecureRandom()` — and BouncyCastle 2.6.2's parameterless `SecureRandom` ctor is `CreatePrng("SHA256",
  autoSeed: true)`, a `DigestRandomGenerator` auto-seeded once from `MasterRandom` whose `CycleSeed`
  mixes only its own seed and a counter, so the generator never consults the OS again and both halves of
  the (key, nonce) pair for methods 0x01/0x02/0x03 come out of that one deterministic stream."
- **security — not refuted:** "Every factual link checks out — the thread-static
  `DigestRandomGenerator(SHA-256)` is OS-seeded exactly once and supplies the salt, the GCM nonce and
  the 0x03/0x05 RSA secret, while ML-KEM's per-call `CryptoServicesRegistrar.GetSecureRandom()`
  genuinely escapes — and although the only concrete break needs a process-checkpoint-restore
  deployment, that hazard class is real and documented, no test or spec section defends the choice, and
  the fix is three lines behind an existing internal seam with no dependency, surface or
  BouncyCastle-isolation consequence, so the cost of hardening is far below the cost of being wrong."
- **reproducibility — not refuted:** "I reproduced the whole chain end-to-end against the shipped DLL —
  `RandomUtils`' thread-static generator is confirmed at runtime to be a SHA-256
  `DigestRandomGenerator` (a closed `state=SHA256(ctr‖state‖seed)` chain that never touches the OS
  again, verified byte-identical over 200 draws spanning 20 seed cycles), and restoring its four fields
  to a captured snapshot made the library emit a byte-identical 53-byte PBKDF2 header (same nonce, same
  salt, same `kcTag`) with `C1 XOR C2 == P1 XOR P2`, letting me recover the second plaintext from the
  first, while the no-restore control differed."

**Strongest surviving counter-argument.** The DRBG belongs to Enigma.Core/BouncyCastle, not here, and
`RandomSourceTests.cs:13` says outright that "this is not a test of the underlying CSPRNG's quality —
that is Enigma.Core's to make", so the delegation could be read as a deliberate boundary; the concrete
break also needs a conjunction of contingencies, and the reproduction forced state duplication by
reflection rather than by an actual snapshot. It survives because the RNG choice is made by **one line
inside this repository** with a one-line local fix that breaks no invariant, and because that test
remark cuts the other way: it shows the repo *assumed* it was being handed an OS-backed CSPRNG. A
general-purpose NuGet library cannot know its deployment, and drawing GCM nonces from a
never-reseeded userland chain is a bet on the consumer's platform that costs nothing to stop making.

---

### F03 — `inputPath == outputPath` deletes the caller's file, because the cleanup delete also covers failures that created nothing

**Severity:** Medium (verifier opinions: Medium / Low / Medium) · **Candidate:** C12
**Location:** `src/Enigma.DataEncryption/DataEncryptionFileExtensions.cs:622-644` (`RunAsync`) and
`:648-663` (`TryDelete`); the incorrect claim is in the remarks at `:617-620`

**What is wrong.** `RunAsync` opens the input, then opens the output **inside the `try`**, and its
`catch` runs `TryDelete(outputPath)` unconditionally. The remarks at `:617-620` state: *"A failure
opening the input happens outside the `try`, where there is no output file to clean up yet — the one
case that must not delete anything."* The author reasoned about the **input** open. The **output** open
is inside the `try` and is a **second** case where nothing was created, and it was not considered. The
suite states the same intent at `DataEncryptionFileExtensionsTests.cs:505-507` — "the cleanup exists to
remove what the operation itself wrote, not to reach for a file it never opened" — and the code enforces
it for only one of the two cases.

**Failure scenario.** `await service.EncryptFileAsync("/data/secrets.txt", "/data/secrets.txt",
Cipher.Aes256Gcm, password)` — a plausible attempt at in-place encryption, and exactly the shape a CLI
wrapper with defaulted arguments produces. Reproduced on .NET 10 / Linux for both
`EncryptFileAsync` and `DecryptFileAsync`: **the file is gone** (`File.Exists == false`). No container
is produced in exchange. Arguments are validated before either file is opened, so no argument check
catches it — each path is individually valid. No test covers the aliasing.

**The mechanism is not the one the candidate claimed**, and all three verifiers corrected it
identically, matching the reproduction I ran independently:

1. `input` opens with `FileShare.Read` — succeeds.
2. Inside the `try`, `output` opens `FileMode.Create, FileAccess.Write, FileShare.None` and **fails with
   `IOException`** ("the process cannot access the file … because it is being used by another process"),
   because the process's own live input handle grants only `FileShare.Read`. .NET defers the
   `O_TRUNC`/`ftruncate` until after the share check, so **the file is not truncated** — it is still
   full-length when the open throws.
3. The `catch` runs `TryDelete(outputPath)`, which is the *input* path, and unlinks it. On Unix,
   `unlink` of a file the process still holds open succeeds.

So there is no "empty input read" and no header/payload interleaving. The destruction is done solely by
the cleanup delete firing for a failure that occurred *while opening* the output.

**Recommended fix.** Reject `inputPath` and `outputPath` resolving to the same file in `ValidateTarget`,
before either is opened — consistent with the existing "arguments validated before either file is
opened" invariant. **String equality is insufficient:** one verifier reproduced the destruction through a
differently-spelled alias (`./name.bin`), so compare resolved paths. Separately, make `TryDelete`
conditional on the call having actually created the output, so the delete cannot fire for a failure that
created nothing — which also fixes the reproduced case of a read-only bystander file at `outputPath`
being deleted by a call that never opened it for write.

**Refutation record.**
- **correctness — not refuted:** "`TryDelete` sits in a `catch` that also encloses the output *open*, so
  a call that never created anything still deletes whatever is at `outputPath` — I reproduced both a
  read-only bystander file and, with `inputPath == outputPath`, the caller's own input being unlinked on
  .NET 10/Linux — which directly contradicts the intent the suite itself states at
  `DataEncryptionFileExtensionsTests.cs:505-507` … a rule the code only enforces for the input-open
  failure."
- **security — not refuted:** "I reproduced it: passing the same path as input and output to any of the
  fourteen wrappers destroys the caller's file on POSIX — not by the truncation the candidate describes,
  but because the failed output open sends control to the `catch` and `TryDelete` unlinks a file the call
  never created, which is exactly what the suite's own comment at
  `DataEncryptionFileExtensionsTests.cs:506` says the cleanup must never do."
- **reproducibility — not refuted:** "I reproduced it independently against the built DLL —
  `EncryptFileAsync(p, p, …)` and `DecryptFileAsync(p, p, …)` both leave `File.Exists(p) == false`, the
  caller's file unlinked by `TryDelete` on a failure that created nothing, with no validation and no test
  anywhere covering the aliasing."

**Strongest surviving counter-argument.** `docs/guides/file-operations.md` already states that an
existing file at `outputPath` is "truncated without warning" and that the partial output is deleted on
any failure, so a caller who names their plaintext as `outputPath` has been told that path's contents are
forfeit — making this documented caller error rather than a library defect. It survives because the call
produces **no container in exchange**, and because the contract's own exhaustiveness claim — "**the one
case** that must not delete anything" — is false as written, which is a defect in the library's stated
reasoning and not merely in the caller's judgement.

**Severity note for PHASE05.** Two verifiers said Medium and one Low, all three noting there is no
adversary. The countervailing consideration is that this is **silent, unrecoverable loss of user data**
from a single plausible call. Whether a non-security defect of that shape outranks the security-relevant
Mediums is a global yardstick question, so it is left to PHASE05 rather than settled here.

---

## Low

### F04 — Method `0x05`'s RSA-OAEP wrap failure is not translated, so Enigma.Core's `CryptographicException` escapes `EncryptAsync`

**Severity:** Low (verifier opinions: Low / Low / Medium) · **Candidate:** C01 · raised independently by
5 of 8 finders
**Location:** `src/Enigma.DataEncryption/Services/HybridDataEncryptionService.cs:176-177` (compare
`RsaDataEncryptionService.cs:249-263`); `docs/guides/hybrid.md:62-63`;
`IHybridDataEncryptionService.cs:101-103`

**What is wrong.** `HybridDataEncryptionService.EncryptCoreAsync` calls
`EncryptOaep(rsaSecret, rsaPublicKeyPem, RsaOaepHash.Sha256)` bare — the enclosing `try` has only a
`finally`, no `catch`. `RsaDataEncryptionService.WrapDataKey` wraps the identical call and converts
`CryptographicException` into `ArgumentException(paramName: publicKeyPem, inner: original)`, per §9's
row: *"RSA OAEP **wrap** failure — the caller's public key is too small for the selected hash
(`CryptographicException`) → `ArgumentException` on the RSA public-key parameter, wrapping it"*, whose
block quote adds that the row *"covers the default SHA-256 as well, where it is reachable for any modulus
below 98 bytes"* — which is exactly the hybrid's fixed wrap (§4). The hybrid's own ML-KEM `Encapsulate`
**is** translated (`:319-334`), so this is an unguarded omission inside a single method rather than a
deliberate asymmetry. This is the one place in the library where an Enigma.Core exception escapes a
public entry point, and the reflection guard cannot see it, because an exception type thrown out of a
method is not part of the reflected surface.

`docs/guides/hybrid.md:62-63` compounds it by claiming the RSA half "takes any modulus size Enigma.Core
will generate" — affirmatively false, since Enigma.Core generates 512- and 768-bit pairs without
complaint and neither can be used at all.

**Failure scenario.** Generate a 512-bit RSA key pair (`RsaKeyFixture.cs:49` already does, for exactly
this reason) and call `hybrid.EncryptAsync(input, output, Cipher.Aes256Gcm, thatPublicKeyPem,
validMlKemPublicKey)`. Reproduced: method `0x03` with the same PEM yields
`ArgumentException{ParamName="publicKeyPem", Inner=CryptographicException}`; method `0x05` yields a raw
`System.Security.Cryptography.CryptographicException` ("RSA OAEP encryption failed…") whose
`InnerException` is `Org.BouncyCastle.Crypto.DataLengthException`. A caller catching
`ArgumentException`/`DataEncryptionException` per the documented contract does not catch it. The
reachable window is **any modulus below 98 bytes** — 768-bit also fails; 1024-bit is the first that
works. The path fails closed: the output stream is verifiably left at **0 bytes** and `rsaSecret` is
cleared by the enclosing `finally`.

Why the green suite misses it: `HybridKeyFixture.cs:44-48` generates only RSA 2048 / 3072 /
unrelated-2048 / encrypted-2048 — **no undersized key**. `RsaFailureTests.cs:527-535` pins the
translated behaviour for `0x03`, and its own doc comment records that before `FEATURE-0D64`
"Enigma.Core's exception escaped unwrapped and undocumented" — the same gap, closed for `0x03` and left
open for `0x05`.

**Recommended fix.** Extract a private `WrapRsaSecret` mirroring `RsaDataEncryptionService.WrapDataKey`:
catch `CryptographicException` and rethrow `ArgumentException` citing RFC 8017 §7.1.1's
`k >= 2·hLen + 34 = 98` for the hybrid's fixed SHA-256, with `nameof(rsaPublicKeyPem)` and the original
as `InnerException`. Add an undersized RSA key to `HybridKeyFixture` and two tests (too-small key →
`ArgumentException` on `rsaPublicKeyPem` with a `CryptographicException` inner; and nothing written to
the output stream). Correct `docs/guides/hybrid.md:62-63`.

**Corrections applied during refutation.** §9's hybrid paragraph enumerates only *decrypt*-side
operations ("an RSA unwrap and an ML-KEM decapsulation"), so the wrap row binds `0x05` through that
paragraph's "inherits both methods' rules verbatim" clause, through §4 making the fixed OAEP-SHA-256 wrap
normative for `0x05`, and through §9's third block quote — **not** through an explicit encrypt-side
sentence. The finder's quotation was slightly stronger than the text. "Five of eight finders raised
this" is corroboration, not evidence, and is not a reason to admit the finding.

**Refutation record.**
- **correctness — not refuted:** "I reproduced it independently against the built library: method 0x03
  with an RSA-512 PEM yields `ArgumentException` on `publicKeyPem` as `docs/format.md` §9 prescribes,
  while method 0x05 with the same PEM lets Enigma.Core's raw `CryptographicException` (inner
  `Org.BouncyCastle.Crypto.DataLengthException`) escape `EncryptAsync`, because
  `HybridDataEncryptionService`'s `EncryptOaep` call at line 176 sits in a `try` with a `finally` and no
  `catch` — and the same method's ML-KEM `Encapsulate` helper does perform the sibling §9 translation, so
  this is an unguarded omission rather than a deliberate asymmetry."
- **security — not refuted:** "The facts hold up under direct inspection — the hybrid's OAEP wrap is the
  one encrypt-side Enigma.Core call in the library left untranslated, against a method-unqualified §9
  row the sibling `Encapsulate` in the same file honours — but the security impact is nil (it fails
  closed with nothing written and the secret cleared, and anyone who can substitute the RSA public key
  already has a total read), so this is a pre-release API-contract conformance fix, not a High-severity
  security defect."
- **reproducibility — not refuted:** "Independently reproduced against the shipped DLL: a 512-bit (and
  768-bit) RSA public key makes method 0x05's encrypt throw a raw
  `System.Security.Cryptography.CryptographicException` with a BouncyCastle `DataLengthException` inside,
  while method 0x03 with the same PEM correctly throws `ArgumentException` on `publicKeyPem` — and the
  hybrid's own adjacent ML-KEM encapsulation failure IS translated, so this is a one-line omission inside
  a single method, not a deliberate asymmetry."

**Strongest surviving counter-argument.** §9 arguably never commits `0x05`'s encrypt side to anything:
the wrap row's block quote is written wholly in method-`0x03` terms (it cites §3.3 and speaks of "the
selected hash", where `0x05`'s hash is fixed), and the "adds no row" paragraph names only decrypt-side
operations — so the row may have no scope over `0x05` at all, leaving the behaviour undocumented rather
than spec-violating. Add that the path requires a cryptographically dead key size and fails closed, and
the whole consequence is a caller seeing one exception type instead of another. It survives on three
grounds: the hybrid already implements the *other* encrypt-side row (`Encapsulate`, whose XML remark says
it makes "the same translation `MLKemDataEncryptionService` makes, and for the same reason"), showing the
author did treat encrypt-side rows as binding on `0x05`; §9 contains no row anywhere mapping any
condition to a bare `CryptographicException`, and opens by declaring the exception "part of the
contract"; and `CLAUDE.md`, which documents every deliberate asymmetry in this repository at length, is
silent on this one. **Exception types become a breaking change after v1.0.0**, which is the real reason
to fix it now rather than later.

---

### F05 — `HeaderReader`'s blanket catches reclassify caller-stream failures as container corruption

**Severity:** Low (verifier opinions: Medium / Low / Low) · **Candidate:** C06 · raised independently by
3 of 8 finders
**Location:** `src/Enigma.DataEncryption/Internal/HeaderReader.cs:110-119`

**What is wrong.** `ReadAsync` wraps the entire parse in `catch (IOException)` →
`DataEncryptionFormatException("The stream ended inside the container header.")` and
`catch (InvalidOperationException)` → `DataEncryptionFormatException("A container header length field is
negative or above its permitted maximum.")`. Neither distinguishes Enigma.Core's own end-of-stream and
length-out-of-range signals from an arbitrary failure raised by the **caller's** stream. §9 licenses only
those two translations, so translating anything else is behaviour the spec does not license, on a type
whose documented meaning is "this is not a container I can parse".

Because `ObjectDisposedException : InvalidOperationException`, **a plainly disposed stream is reported as
a malformed length field** — a statement that is simply false. No service validates `input.CanRead`
(`grep -rn "CanRead" src/` hits only `HeaderReader.TeeStream:374`), so this needs no custom stream and no
mid-header failure: a disposed `MemoryStream` or `FileStream` handed straight to `DecryptAsync` throws on
the first read of the magic and is misreported, and `IEncryptedDataInspector.ReadHeaderAsync` misreports
it identically. The behaviour is also internally inconsistent — the same `IOException` raised while
reading the **payload** propagates unwrapped, and four passing test suites depend on that.

**Failure scenario.** Reproduced with a stream that yields 20 valid header bytes and then throws:
`IOException("The device is not ready.")` → `DataEncryptionFormatException("The stream ended inside the
container header.")`; `ObjectDisposedException` → `DataEncryptionFormatException("A container header
length field is negative or above its permitted maximum.")`; an unrelated `InvalidOperationException` →
the same false message. Controls behave correctly: genuine truncation gives the first message, and
`UnauthorizedAccessException` propagates. `docs/guides/file-operations.md:335-350` tells callers to catch
`DataEncryptionFormatException` as "Not an Argon2 container" and `IOException` as "File error" — so a
backup tool following the library's own documented caller pattern reports a transient network blip as
archive corruption, and a disposed-stream programming bug as corruption too.

**Recommended fix.** Narrow both catches. For the second, a one-line
`when (exception is not ObjectDisposedException)` filter. For the first, set a flag inside the existing
`TeeStream` when `_inner.Read*` itself throws, and re-throw when the `IOException` did not originate in
Enigma.Core's read helpers. At minimum, reword both messages so they say the header "could not be read"
and defer the cause to `InnerException` instead of asserting a specific one.

**Corrections applied during refutation.**
- **Diagnosability is not lost:** both catches pass the original as `InnerException`, and
  `HeaderTruncationTests.TheUnderlyingIoExceptionIsPreservedAsTheInnerException` pins that. The defect
  is confined to the exception **type** and the **message text**.
- The finder's first proposed fix — counting bytes consumed against the expected header length — **does
  not work**: a read that throws and a read that returns 0 leave the mirror short by the same amount.
- Reachability is *understated*, not overstated: the `ObjectDisposedException` arm needs no mid-header
  failure at all.
- The catch is not a blanket "caller-stream failures" reclassifier: it captures exactly `IOException` and
  `InvalidOperationException`-derived types. `OperationCanceledException`/`TaskCanceledException` derive
  from `SystemException`, so **§9's cancellation row is unaffected**, and no cryptographic operation runs
  inside the guarded block, so no crypto failure can be masked.

**Refutation record.**
- **correctness — not refuted:** "Confirmed by independent reproduction against the built library: a
  caller-stream `IOException` mid-header becomes `DataEncryptionFormatException("The stream ended inside
  the container header.")`, and because `ObjectDisposedException : InvalidOperationException`, even a
  plainly disposed `MemoryStream` — failing on the very first read, on the inspector path as well — is
  reported as "A container header length field is negative or above its permitted maximum", a statement
  that is simply false, while the identical `IOException` in the payload propagates unwrapped, and
  `docs/guides/file-operations.md:335-350` tells callers to catch `DataEncryptionFormatException` as
  "Not an Argon2 container" and `IOException` as "File error", so the library's own documented caller
  pattern is the thing this conflation misleads."
- **security — REFUTED:** "Neither trigger is adversarial — a transient device/network `IOException` is
  not attacker-controlled (and an attacker who owns the storage path can already corrupt or withhold the
  file outright), while `ObjectDisposedException` requires the caller to dispose its own stream mid-read,
  i.e. a caller bug — and in both cases the real cause is preserved verbatim as `InnerException` …, so no
  confidentiality, integrity, authentication or key-material property is weakened and the attacker gains
  nothing they did not already have; the file-quarantining data-loss story rests on an invented
  downstream caller, not on anything this library does."
- **reproducibility — not refuted:** "I reproduced every line of the claim against the shipped DLL and
  found the real case is worse than stated — handing a genuinely disposed `MemoryStream` or `FileStream`
  straight to `DecryptAsync` (no custom stream, and no service validates `input.CanRead`) yields
  `DataEncryptionFormatException` "A container header length field is negative or above its permitted
  maximum", an affirmatively false statement about a caller-side programming bug, while the identical
  `IOException` in the payload propagates unwrapped in four passing test suites that depend on it."

**Strongest surviving counter-argument.** `HeaderTruncationTests`' class remarks state the design goal
explicitly — either exception "escaping `HeaderReader` would leak an implementation detail into the
public contract of §9, so both must be gone by the time the reader returns" — so the blanket catch is a
deliberate mechanism, and §9 already establishes a house precedent (the wrong RSA private key, ML-KEM
`Decapsulate`) that when two causes are indistinguishable without matching on message text the container
classification wins and the true cause is preserved as `InnerException`. It survives because the stated
rationale is about not leaking *Enigma.Core's* exceptions, whereas the caller's own
`ObjectDisposedException` is not Enigma.Core's implementation detail; because unlike `DecryptOaep` and
`Decapsulate` the distinction here **is** mechanically available without message text; and because
`DataEncryptionFileExtensions.cs:181` positively documents `IOException` for a file that "could not be
opened, read or written", so a header-phase read failure contradicts the public XML contract rather than
merely falling outside §9's table.

---

### F06 — The `char[]` password overloads fault the returned `Task` where the `byte[]` overloads throw at the call site

**Severity:** Low (verifier opinions: Low / Observation / Low) · **Candidate:** C09
**Location:** `src/Enigma.DataEncryption/Services/Pbkdf2DataEncryptionService.cs:101-105` and
`:132-135`; `Argon2DataEncryptionService.cs:104-108` and `:135-138`

**What is wrong.** The `byte[]` overloads validate everything up front and carry the comment
*"Validation is synchronous — an argument mistake faults the call, not the returned task — and runs in
declaration order, so the first parameter at fault is the one reported."* The `char[]` overloads validate
only the password, then return an `async` helper, so the null-stream, cipher and positive-cost checks are
reached inside the state machine and arrive as a faulted `Task`. The same intent is written twice more,
at `MLKemParameterSetWire.cs:47` and `RsaOaepHashWire.cs:69` ("so that a service can fault
synchronously, before it returns a task"), and `DataEncryptionFileExtensions.cs:88-93` hoists the checks
on **both** credential shapes — so the file wrappers already behave the way this asks the stream
overloads to. These four are the library's only exception: RSA, ML-KEM and the hybrid have one credential
shape each and validate everything synchronously.

**Failure scenario.** `Task t = pbkdf2.EncryptAsync(null!, output, Cipher.Aes256Gcm, passwordChars)`
returns a faulted `Task` without throwing, while the `byte[]` sibling throws at the call site. Reproduced
for all eight combinations (null stream, undefined cipher, zero cost, on both services and both
directions). A **fire-and-forget** caller loses the `ArgumentNullException` entirely to the
unobserved-exception path, where the `byte[]` overload would have crashed the caller's frame immediately.
Because the `char[]` overloads validate the password *first*, when two arguments are bad at once the
reported `ParamName` can also differ from the `byte[]` overload's declaration-order answer.

**Recommended fix.** Hoist the same checks into the two `char[]` overloads before the call to the async
helper, in declaration order, accepting the duplicated checks in the inner `byte[]` overload as cheap.

**Corrections applied during refutation.** Frame this as a **cross-overload inconsistency with the
house's own stated intent, not a spec violation**: `docs/format.md` says nothing about synchronous versus
faulted delivery, §7.1 step 1 is satisfied by both shapes, and `<exception>` tags on `Task`-returning
members conventionally describe what the operation raises rather than where. The finder's
"mid-batch `AggregateException`" is wrong — `await Task.WhenAll(tasks)` rethrows only the first inner
exception; an `AggregateException` needs `.Wait()`/`.Result`. The fire-and-forget half is the accurate
one.

**Refutation record.**
- **correctness — not refuted:** "Re-running the probe against the shipped assembly confirms all four
  `char[]` overloads of both password services validate only the password before handing off to an
  `async` helper, so a null stream, an undefined `Cipher` or a non-positive cost is captured into the
  returned `Task` (`IsFaulted=True`) where the `byte[]` siblings throw at the call site — exactly
  contradicting the intent written into the `byte[]` overloads' own comment and into the
  `ValidateArgument` remarks at `Internal/MLKemParameterSetWire.cs:47` and `Internal/RsaOaepHashWire.cs:69`."
- **security — REFUTED:** "Factually accurate but security-inert: the trigger is a caller-side coding
  mistake (null stream, undefined cipher, non-positive cost) that no attacker can influence, the
  exception type reaching an `await` is identical either way, and
  `PasswordArgumentValidationTests.ARejectedCallWritesNothingAndDerivesNothing` already pins the only
  invariant with security content — a rejected call writes no output byte and spends no KDF work — for
  both credential shapes."
- **reproducibility — not refuted:** "I reproduced all four locations against the shipped net10.0
  assembly — the `byte[]` overloads throw `ArgumentNullException`/`ArgumentOutOfRangeException`
  synchronously for a null stream, an undefined cipher and a zero cost, while the `char[]` siblings
  return an already-faulted `Task` for the identical inputs … and nothing in `docs/format.md`,
  `CLAUDE.md` or the test suite sanctions or pins the split, whereas the `byte[]` overloads' own comment,
  the … remarks in `MLKemParameterSetWire`/`RsaOaepHashWire`, and the `char[]` *file* wrappers (which do
  validate everything up front) all state the opposite intent."

**Strongest surviving counter-argument.** Nothing normative is violated: the only contract clause about
validation timing is §7.1 step 1, which both shapes honour — no salt or nonce drawn, no key derived, no
byte written either way — and `PasswordArgumentValidationTests` deliberately exercises both shapes
through `Assert.ThrowsAsync` and passes, which is the observable contract the suite pins. For the
overwhelmingly common `await svc.EncryptAsync(...)` shape the behaviour is identical. It survives because
the Task-based Asynchronous Pattern guidelines do say usage errors should be thrown synchronously, the
house asserts that property in three separate places, the file wrappers already implement it on both
shapes, and a fire-and-forget caller does lose the diagnostic entirely.

---

### F07 — No payload-length ceiling: a payload above GCM's `2^36 − 32` byte limit raises an untranslated `InvalidOperationException`

**Severity:** Low (verifier opinions: Low / Observation / Low) · **Candidate:** C10 · raised
independently by 2 of 8 finders
**Location:** `src/Enigma.DataEncryption/Internal/PayloadCipher.cs:44-64` (encrypt: no `catch` at all)
and `:92-111` (decrypt: `CryptographicException` only); `docs/format.md` §4 and §8

**What is wrong.** SP 800-38D §5.2.1.1 caps GCM plaintext at `2^39 − 256` bits = `2^36 − 32` bytes
(≈ 64 GiB) per (key, IV). Neither §4 (Fixed parameters) nor §8 (Limits) mentions a payload maximum, so
the contract states every other invariant and limit and is silent on the one that actually exists.
BouncyCastle *does* enforce it — `GcmBlockCipher` sets `blocksRemaining = 4294967294u` and throws
`InvalidOperationException("Attempt to process too many blocks")` — so **there is no keystream reuse**.
But that type is translated by nobody on the payload path: Enigma.Core's `BlockCipherService` catches
only `CryptoException`, `PayloadCipher.EncryptAsync` catches nothing, and `DecryptAsync` catches only
`CryptographicException`. So it escapes raw, outside this library's exception hierarchy.

**Failure scenario.** Reproduced end to end: encrypting 68,719,480,832 bytes through
`IPbkdf2DataEncryptionService.EncryptAsync` fails after 68,719,472,709 output bytes with a raw
`System.InvalidOperationException("Attempt to process too many blocks")` from
`GcmBlockCipher.ProcessBytes`, surfacing through `Pbkdf2DataEncryptionService.EncryptCoreAsync:173` with
`is DataEncryptionException: False`. The throw lands on the first 4,096-byte chunk that would cross the
cap, and Enigma.Core's `finally` still appends a 16-byte tag without masking the original exception. A
caller encrypting a disk image or database backup — squarely in scope for a library whose README is about
"arbitrary data and streams" — catches `DataEncryptionException` per the XML docs and §9 and sees an
unhandled `InvalidOperationException`. The malformed-input sweep cannot catch it: it would need a 64 GiB
fixture.

**Recommended fix.** Add a normative row to §4 — maximum payload `2^36 − 32` bytes (68,719,476,704),
citing SP 800-38D §5.2.1.1 — and either reject a longer input up front where `input.CanSeek`, or at
minimum translate `InvalidOperationException` in both `PayloadCipher` methods
(`DataEncryptionException` on encrypt, `DataDecryptionException` on decrypt). The translation alone is a
three-line change.

**Corrections applied during refutation.** **"§9's closed exception list" overstates the spec.** §9 opens
"The exception a reader raises is part of the contract" and maps enumerated *container conditions*, but
never declares the table exhaustive, and demonstrably is not: it already carries propagate-unwrapped
rows, and a mid-payload `IOException` from a caller stream escapes untranslated today by design
(documented at `docs/guides/file-operations.md:83`). `MalformedContainerSweepTests.cs:12-38` scopes its
closed-set invariant to "corrupted and truncated containers", which a well-formed 68 GB payload is not.
And §8's "Every variable cost and length field is bounded" is explicitly about **header** fields. So the
correct framing is a **documentation gap in §4/§8 plus an untranslated exception**, not a
doc-versus-code contradiction. The same untranslated-exception class covers a throwing
`IProgress<int>` implementation, which was separately reproduced to propagate `InvalidOperationException`
raw out of both directions (with 4,096 bytes already released on decrypt) — recorded here rather than as
its own finding, and relevant to PHASE03's negative-space list.

**Refutation record.**
- **correctness — not refuted:** "The mechanism checks out end to end — BouncyCastle 2.6.2's
  `GcmBlockCipher` sets `blocksRemaining = 4294967294u` and throws `InvalidOperationException("Attempt
  to process too many blocks")`, Enigma.Core's `BlockCipherService` catches only `CryptoException` …,
  `PayloadCipher.EncryptAsync` catches nothing and `DecryptAsync` only `CryptographicException`, and no
  payload ceiling exists in `DataEncryptionLimits`, the file wrappers or `docs/format.md` — so a payload
  past `2^36 − 32` bytes really does surface an exception outside this library's hierarchy; only the
  finding's *framing* is overstated, not its substance."
- **security — REFUTED:** "The candidate concedes BouncyCastle enforces the GCM block cap, so the
  construction fails closed with no keystream reuse and no confidentiality or integrity loss; what
  remains is an exception type at a 68.7 GB boundary that an attacker can only reach by transferring
  68.7 GB for zero amplification, gaining nothing but a different exception name — and §9 is not the
  closed list the candidate assumes."
- **reproducibility — not refuted:** "Reproduced end to end against the shipped assembly — encrypting
  68,719,480,832 bytes through `IPbkdf2DataEncryptionService.EncryptAsync` fails after 68,719,472,709
  output bytes with a raw `System.InvalidOperationException("Attempt to process too many blocks")` …
  with `is DataEncryptionException: False`, so the claim holds exactly as stated."

**Strongest surviving counter-argument.** The `2^32 − 2`-block cap is a property of GCM itself, enforced
correctly by the primitive with zero security consequence; the library did nothing wrong and cannot raise
the ceiling; and §9 maps container conditions rather than resource-class failures, so a 64 GiB boundary
arguably sits outside its remit. It survives because §4 and §8 exist precisely to state the format's
invariants and limits and are silent on a real one, because `CLAUDE.md` advertises the sweep as proving
"never an unwrapped Enigma.Core failure", and because the fix is three lines plus one normative row —
cheap enough that "unreachable in practice" is a weak defence for a library that advertises arbitrary
streams.

---

### F08 — Method `0x03`'s key-confirmation-mismatch message names a cause OAEP has already excluded

**Severity:** Low (verifier opinions: Low / Observation / Low) · **Candidate:** C14
**Location:** `src/Enigma.DataEncryption/Services/RsaDataEncryptionService.cs:203-204`

**What is wrong.** The message reads *"The RSA private key is wrong: the container's key-confirmation tag
does not match the unwrapped data key."* But a wrong private key fails inside `UnwrapDataKey` and is
reported there with a **different** message (pinned by `RsaFailureTests.TheWrongPrivateKeyIsADecryptionError`
and `APrivateKeyOfADifferentSizeIsADecryptionError`), so line 204 is reachable **only when the unwrap
succeeded** — i.e. when the private key does match the field it decrypted. The leading clause is
therefore false in every case that can reach it. §6.3 already states the reasoning for the hybrid ("neither
is a sender who wraps one value under RSA while combining another"), and
`HybridDataEncryptionService.cs:285` spells out the analogous "neither primitive could report this"
caveat that `0x03`'s message omits.

**Failure scenario.** The reachable causes are all **file-content** faults: an inconsistent producer
(a hostile or buggy sender who wrapped one 32-byte value and tagged another —
`RsaFailureTests.AWrappedKeyHoldingTheWrongDataKeyIsCaughtByKeyConfirmation`'s own doc comment says "A
hostile sender holding the recipient's public key can build exactly that"), **or any parseable edit to a
header byte before the tag** — the nonce at offsets 6-17, read unvalidated, or the cipher byte flipped
between two valid values, which the suite already exercises in
`EditingTheCipherByteToAnotherValidCipherIsADecryptionError` while asserting only the exception type. In
every one of those, a caller whose credential is fine is told their private key is wrong, and may rotate
or re-issue a good key pair while the real fault — a tampered or corrupt container — goes uninvestigated.

**Recommended fix.** Reword to state the reachable condition: the wrapped key was recovered successfully
but does not match the key the container's tag was computed under, so the container was produced
inconsistently or its contents were altered. The hybrid's message is the model.

**Corrections applied during refutation.** The reachable set is **wider** than the candidate claimed (any
parseable pre-tag header edit, not only an inconsistent producer), which broadens the misattribution. The
candidate's "correct-but-unrelated container" prong is **unreachable** — that fails at OAEP and yields the
other message. The message string is not normative anywhere: `grep` for "private key is wrong" under
`docs/` returns nothing, so this is a non-contractual human hint rather than a documented promise, which is
why it is Low. The same "the credential is wrong" phrasing pattern is shared by all five methods, so a fix
should keep the house voice.

**Refutation record.**
- **correctness — not refuted:** "`UnwrapDataKey` (line 195) converts every OAEP failure — including a
  wrong private key — into its own `DataDecryptionException`, so line 204 is reachable only when the
  unwrap succeeded and yielded 32 bytes, i.e. when the private key does match the key the wrapped-key
  field was encrypted under, making the message's leading clause "The RSA private key is wrong" false in
  every case that can actually reach it."
- **security — REFUTED:** "The branch fires only after the container has already been rejected before a
  single payload byte is read, the exception *type* — the only thing `docs/format.md` §9 makes
  contractual — is correct, and §9's own closing gloss assigns "in practice, the wrong credential" to the
  whole `DataDecryptionException` class, so a coarse credential-shaped hint is spec-aligned rather than
  spec-contradicting, and no adversary gains anything they did not already hold."
- **reproducibility — not refuted:** "Traced concretely: a wrong RSA private key always fails inside
  `UnwrapDataKey` with a different message …, and every path that actually reaches line 204 is a
  file-content fault — an inconsistent producer, or any edit to a header byte before the tag such as a
  corrupted nonce or a cipher byte flipped to another valid value — so the message blames the caller's
  credential for a condition whose own precondition proves that credential correct, exactly as
  `docs/format.md` §6.3 and `HybridDataEncryptionService.cs:225` both already state."

**Strongest surviving counter-argument.** §6.2 characterises any tag mismatch generically as "a
decryption error (wrong credential)", all five services deliberately share one wording pattern, no message
text is normative, and the part §9 makes contractual — the exception type — is correct. It survives
because the library's own hybrid message proves the house knows how to say the accurate thing, and because
an operator acting on "The RSA private key is wrong" after a wrapped-key substitution or a nonce
corruption takes precisely the wrong remedial action.

---

### F09 — `docs/format.md` states no non-goals: replay and freshness are absent from the format and undocumented anywhere

**Severity:** Low (verifier opinions: Low / Observation / Low) · **Candidate:** C16
**Location:** `docs/format.md` (ends at §10, no non-goals section); `README.md`; `SECURITY.md`; all seven
guides; every XML doc in `src/`

**What is wrong.** The specification enumerates what the container **does** provide in detail and never
states what it does not. A container carries no timestamp, sequence number, expiry, or binding to a
recipient identity, session or filename, so a captured container is re-deliverable indefinitely and an
application has no in-format signal to detect it. An exhaustive grep of `docs/format.md`, all seven
guides, `README.md`, `SECURITY.md`, `RELEASENOTES.md` and every XML doc comment finds **no occurrence** of
*replay*, *freshness*, *timestamp*, *expiry* or *forward secrec*. The document demonstrably knows how to
state a non-guarantee — §3.5.2's closing paragraph says a successful decrypt proves the container was made
*for* the recipient, not *by* anyone, and §3.3/§3.4 say the same — and simply does not do so here.
`docs/plan/FEATURE-F612.md:183-185` pre-designates "replay protection … absent *and* undocumented" as a
finding against the docs.

**Failure scenario.** An integrator reads §5 and §6.3, concludes the container is authenticated and
key-committing, and builds a workflow in which a container is a bearer credential — a queue consumer that
acts on each container it can decrypt. An attacker who captured one container replays it N times; every
copy decrypts successfully and identically, and nothing in the library or the spec flags it. For the two
**password** methods this is a genuine gain: an attacker who cannot forge a container can still
re-deliver one.

**Recommended fix.** Add a short subsection — "§11 Properties not provided" — stating explicitly that the
format offers no freshness or replay protection (no timestamp, sequence number, expiry, or binding to a
recipient identity or session; an application needing it must supply it outside the container or inside the
plaintext), and cross-reference the sender-authentication non-guarantee the document already writes three
times so all of them sit together.

**Corrections applied during refutation, which narrow this finding materially.**
- **The forward-secrecy half is dropped.** It is unobtainable by construction for a store-then-decrypt
  container opened with a long-term key, it is not among the four non-guarantees the item's own plan names,
  and the candidate mis-traced it to §3.5.2 — which already says `K` is good "unless **both** secrets are
  recovered", i.e. states the opening condition rather than implying forward secrecy. What remains is the
  replay/freshness/context-binding omission alone.
- **The claim that §6.3 and §3.5.2 "invite the opposite inference" is withdrawn.** §6.3 defines key
  commitment narrowly and completely inline; §3.5.2 is explicitly bounded by its own "What is *not*
  claimed" and "Authentication is not part of the claim either" paragraphs;
  `docs/guides/hybrid.md:351-352` says "Holding one of the two private keys is worth nothing". The finding
  rests on **silence**, not on any misleading sentence, and should be filed that way.
- For the three public-key methods the bearer-credential scenario is largely foreclosed already: anyone
  holding the public keys can mint a fresh valid container, so replay grants little. The residue is
  strongest for `0x01`/`0x02`.

**Refutation record.**
- **correctness — not refuted:** "§§2–10 of `docs/format.md` contain no freshness field … and no non-goals
  section, and an exhaustive grep of `docs/format.md`, all seven guides, `README.md`, `SECURITY.md`,
  `RELEASENOTES.md` and every XML doc comment in `src/` finds no occurrence of replay, freshness, forward
  secrecy, bearer, expiry or timestamp anywhere — so the gap is real, and the repo's own audit plan
  (`docs/plan/FEATURE-F612.md:183-185`) names "replay protection" as exactly the case where "absent *and*
  undocumented is a finding against the docs"."
- **security — REFUTED:** "The spec is silent, not wrong — it never claims freshness or forward secrecy;
  forward secrecy is unobtainable by construction for any non-interactive container opened with a
  long-term credential, so there is no library defect to fix; and the "container as bearer credential"
  failure scenario is already foreclosed by the non-guarantee §3.3/§3.4/§3.5.2 and all three public-key
  guides do state … — leaving a documentation-completeness wish with no reachable security consequence."
- **reproducibility — not refuted:** "The core claim reproduces exactly as stated — no file under
  `docs/`, `README.md`, `SECURITY.md` or the XML docs contains "replay", "freshness", "timestamp",
  "expiry" or "forward secrec" (grep returns nothing), `docs/format.md` ends at §10 with no non-goals
  section, the services are documented stateless so a replayed container does decrypt identically every
  time … — so only the candidate's forward-secrecy illustration, not the finding itself, is wrong."

**Strongest surviving counter-argument.** No file-at-rest format — age, OpenPGP, CMS, 7-Zip AES —
documents the absence of replay protection, both freshness and forward secrecy being properties of
interactive protocols rather than of a container that must stay decryptable by a long-term key forever; and
`CLAUDE.md` scopes `docs/format.md` as the contract for "every offset, size and constant", so silence about
a protocol-layer property is not a contract defect. It survives narrowly, and only for the two password
methods: for those an attacker who cannot forge does gain something by re-delivery, the document already
writes three sender-authentication non-guarantees so a fourth costs a paragraph, and this item's own plan
named replay protection in advance as the case where undocumented absence counts.

---

### F10 — `DataDecryptionException`'s shipped XML documentation states the opposite of §9, the code, and a passing test

**Severity:** Low (verifier opinions: Low / Low / Low — unanimous) · **Candidate:** C19
**Location:** `src/Enigma.DataEncryption/Exceptions/DataDecryptionException.cs:15-19` (prose on 16-18)

**What is wrong.** The remarks on the public exception type say: *"A malformed **or undecryptable**
private-key PEM is **not** reported through this type: that is a credential-supply error rather than a
container error, and Enigma.Core's own exception propagates unwrapped. See `docs/format.md` §9."*

`docs/format.md:581` says the opposite for the *undecryptable* half — *"RSA OAEP unwrap failure,
**including an undecryptable private-key PEM** (`CryptographicException`) → `DataDecryptionException`,
wrapping it"* — reserving the propagate-unwrapped rule for a PEM that cannot be **parsed**. §9 uses
*undecryptable* and *unparseable* as deliberately contrasting terms, and the remark collapses them.
`RsaDataEncryptionService.UnwrapDataKey` implements and documents §9's rule in bold, and
`RsaFailureTests.AnUndecryptablePrivateKeyPemIsADecryptionErrorWithTheCauseInside` proves it. The
paragraph is **self**-contradictory too: the same type's bullet at line 13 already lists "an RSAES-OAEP
unwrap failure, likewise wrapping the underlying `CryptographicException`". One verifier traced it to a
verbatim survival of the pre-amendment row, still visible at `docs/plan/FEATURE-00E7.md:312`. It ships in
the packed `.xml` (`GenerateDocumentationFile` is on), so it reaches every consumer's IntelliSense.

**Failure scenario.** Reproduced: an encrypted RSA private-key PEM opened with a wrong passphrase, and
with none, both throw `DataDecryptionException` with an inner `CryptographicException`, while an
unparseable PEM propagates as `FormatException`. A consumer who follows the type's remarks routes
wrong-passphrase handling into a `catch (ArgumentException/FormatException)` branch that **never fires**,
so their wrong-passphrase path is dead code.

**Recommended fix.** Correct the paragraph to match §9: an undecryptable private-key PEM (wrong
passphrase, or an encrypted PEM opened with none) **is** reported through this type with the
`CryptographicException` preserved as `InnerException`; only a PEM that cannot be **parsed** propagates
unwrapped. A single-paragraph edit to one file.

**Corrections applied during refutation.**
- **Do not bundle `DataEncryptionFormatException`.** Its remarks open "Raised for, **among others**:" and
  every listed cause is accurate, so omitting the OAEP-hash byte and the 32-byte wrapped-key check is
  incompleteness by design, not a contradiction. The candidate's secondary recommendation is withdrawn.
- The exposure is narrower than "every consumer's IntelliSense": the docs a consumer reads **at the call
  site** — `IRsaDataEncryptionService.cs:126` and `IHybridDataEncryptionService.cs:164-172` — are correct
  and explicitly name the wrong-passphrase case, and the thrown message itself names the cause. That
  containment is why all three verifiers rated this Low.

**Refutation record.**
- **correctness — not refuted:** "`DataDecryptionException.cs` line 16 states in bold that an
  "undecryptable private-key PEM is **not** reported through this type" and cites §9, while
  `docs/format.md:581` puts exactly that case in this type …, `RsaDataEncryptionService.UnwrapDataKey`
  implements and documents it that way, `IRsaDataEncryptionService.cs:126` documents it correctly, and
  `RsaFailureTests.AnUndecryptablePrivateKeyPemIsADecryptionErrorWithTheCauseInside` proves it — the wrong
  sentence is a verbatim survival of the pre-amendment row still visible at
  `docs/plan/FEATURE-00E7.md:312`, and it ships in the packed `.xml`."
- **security — not refuted:** "Verified on all three axes: the remarks shipped on the public
  `DataDecryptionException` type assert the exact opposite of §9's amended row, of
  `RsaDataEncryptionService.cs:276`'s bold note and of a passing test, and they are stale since the
  pre-amendment skeleton commit — a genuine contract defect worth a one-paragraph fix, but with no
  adversary anywhere in the story it is Low, not Medium."
- **reproducibility — not refuted:** "I reproduced the real behaviour against the built DLL — an encrypted
  RSA private-key PEM opened with a wrong passphrase, and with no passphrase, both throw
  `Enigma.DataEncryption.DataDecryptionException` with an inner `CryptographicException` (while an
  unparseable PEM does propagate as `FormatException`), so `DataDecryptionException`'s shipped remarks …
  are affirmatively wrong on the "undecryptable" half and contradict the very section they cite."

**Strongest surviving counter-argument.** The sentence could be read as a loose pairing rather than a
false statement — "malformed or undecryptable" as one idea, "a PEM this library cannot turn into a key" —
and the member-level `<exception>` doc a consumer sees while typing the call is correct and explicit about
the wrong-passphrase case, so no runtime behaviour, wire format or security property is affected. It
survives on this repository's own terms: §9 uses *undecryptable* and *unparseable* as deliberately
contrasting terms, `CLAUDE.md` records the distinction as a load-bearing outcome of `FEATURE-11B6`
PHASE03, and the remark cites the very section it contradicts.

---

# Observations

Informational. **These do not become phases of the `CODE-REVIEW` item.** Each was put through the same
three-lens refutation and failed to reach 2 of 3, but contains something worth recording.

**O01 — The encrypt path bounds cost parameters only by `> 0`, so the library can write containers its
own default-limits reader refuses.** (Candidate C04, 1/3 — reproducibility not refuted, Low; correctness
and security refuted, Observation.) `Argon2DataEncryptionService.cs:84-86`,
`Pbkdf2DataEncryptionService.cs:82-86`, `DataEncryptionLimits.cs:31-47`. Reproduced verbatim: RFC 9106
§4's **first** recommended option (t=1, m=2 GiB, p=4) encrypts happily and then fails default-limits
decrypt with "Header field 'Argon2 memory size in KiB' is 2097152, which exceeds the maximum of 1048576";
`memorySizeKb: 1024` with `degreeOfParallelism: 100000` allocates gigabytes despite the caller asking for
1 MiB, because BouncyCastle requires `m >= 8p` and clamps upward; and `degreeOfParallelism >= 16,777,216`
throws a bare `InvalidOperationException` where §9's out-of-range-argument row promises
`ArgumentOutOfRangeException`. No test bounds any encrypt-side cost argument above zero. **Why it did not
become a finding:** §8, the `DataEncryptionLimits` XML doc and `docs/guides/password-based.md:60` all scope
the caps to fields *read from a header*, as a hostile-container defence; "a writer can exceed the default
reader cap" is a property of having a finite configurable cap at all, and binding the writer to the
reader's default would remove the caller's ability to exceed it deliberately. The one part that is not
policy is the bare `InvalidOperationException` at extreme parallelism, which is the same untranslated-type
class as F07.

**O02 — No joint `m >= 8p` check, so a container can be written that a reference-compliant reader refuses
outright.** (Candidate C05, 1/3 — reproducibility not refuted, Low; the other two refuted, Observation.)
`Argon2DataEncryptionService.cs:84-86`, `Internal/LimitsValidator.cs:34-43`. RFC 9106 §3.1 requires
`m >= 8p`; neither path enforces it. Reproduced: `EncryptAsync(t=3, m=64, p=32)` succeeds and round-trips,
the header records `mem=64`, and Enigma.Core/BouncyCastle derive a key that `libargon2` **refuses to
produce at all** ("Error: Memory cost is too small"), while the two agree byte-for-byte for the RFC-legal
`m=256, p=32`. So a container written with sub-threshold parameters is unopenable by a reader implementing
§3.2's unconditional `Argon2id(…)` equation — the hand-written third-party reader §1.1 says the spec exists
to support. **Why it did not become a finding:** the correctness lens verified that the clamp does **not**
collapse distinct memory values (at p=32, m=64/65/255/256 each yield a different key), so §3.2 still
designates a deterministic function of exactly the parameters the header records; the clamp only ever
*raises* memory, so the KDF is never cheaper than requested; and it requires the caller to pass
self-contradictory costs that no default, guide or test uses.

**O03 — A cancelled or aborted stream encryption leaves a complete, self-authenticating container over a
truncated plaintext.** (Candidate C11, 1/3 — correctness not refuted, Low.) `PayloadCipher.cs:44-64`.
Because Enigma.Core disposes its `CipherStream` in a `finally` and `CipherStream.Dispose` calls `DoFinal`,
an encrypt aborted by a source-stream `IOException`, a cancelled token or a throwing `IProgress` still
writes a valid GCM tag, so the short container parses, passes key confirmation and decrypts cleanly as a
prefix of the intended plaintext. The header records no plaintext length, so no reader can detect it.
**Why it did not become a finding:** every reachable path delivers an exception to the caller
(`TaskCanceledException`/`IOException`), the file wrappers' tested delete-on-failure covers the file path,
a genuinely *killed* process never runs the `finally` so the tag is absent and the reader does reject, and
the residue — "a source stream that reports EOF early is believed" — is inherent to any single-tag streamed
AEAD and contradicts no statement in `docs/format.md`.

**O04 — Two stale XML doc comments** (found while reading; not put through refutation, and forwarded to
PHASE04 which owns the XML-docs dimension). `EncryptedDataInspector.cs:32-33` says the inspector "reads all
four" methods — there have been five since `FEATURE-5A30`. And `HybridKeyCombiner`'s remarks attribute the
header-slice assertion to `HybridKeyCombinerTests`, whereas it lives in
`HeaderGoldenBytesTests.HybridHeader_ContainsTheCombinerTranscriptAsAContiguousSlice`.

**O05 — `DataEncryptionLimits` validates none of its own `init` properties**, so
`new DataEncryptionLimits { MaxArgon2MemorySizeKb = int.MaxValue }` makes the
arithmetic-not-computation promise vacuous. Dropped by its finder as caller-owned: §8 frames the caps as a
knob for tightening, so this is a configuration footgun rather than a defect in the default posture.

**Line endings.** No CRLF/LF inconsistency was observed in the files read. Recorded here because the house
rule makes anything about line endings an Observation and never a finding.

---

# Considered and refuted

Suspected, investigated, and found **not** to be defects. Recorded so the next reviewer does not repeat
the work, and so the reasoning can be argued with.

**R01 — "The default Argon2 caps multiply, so a 61-byte header buys ~1 GiB and ~61 s of uninterruptible
work."** (C03, refuted 3/3.) The measurement is real — forged max-cost headers cost 1,283 ms at 1 GiB × 1
pass and 7,628 ms at 8 passes, extrapolating to ~61 s at the 64-pass cap — but the conclusion does not
follow. §8's "gigabytes or hours" sentence is immediately qualified by "survivable, not sensible" and its
own table publishes the 1 GiB cap three lines above; `docs/guides/password-based.md:227-248` states outright
that "nothing stops someone handing you a container claiming a 1 GiB Argon2 memory cost" and shows the exact
tightened-limits recipe the candidate proposed; and `LimitsValidatorTests.Argon2_AtEveryCap_IsAccepted` plus
`HeaderValidationTests.CostFieldsAtTheCapAreAccepted` pin all-caps acceptance as intended. A product bound
would not lower the peak allocation either, since that is governed by `memorySizeKb` alone — and PBKDF2's
single knob already buys 4,510 ms from a 53-byte header with no product to bound. **This is deliberate
choice 8 working as documented; reporting it would send a maintainer to reverse a documented, tested,
caller-configurable policy.**

**R02 — "The KDF runs synchronously before the returned Task yields."** (C08, refuted 3/3.) The
encrypt-direction blocking is real and was measured at 166–573 ms at the library's own defaults against a
9 ms RSA control. But the finding as written fails: the **decrypt** direction it also named moves the
derivation off the caller's thread whenever the header read completes asynchronously (2–3 ms synchronous
through the real file wrappers), and the original 1,283 ms decrypt figure was measured over a `MemoryStream`
whose awaits never yield, so it measured nothing about statement ordering. The 1.4 s headline was taken at
3,000,000 iterations, five times the default. The ASP.NET half is backwards — a CPU-bound derivation
occupies one thread for the same duration whether or not the method yields first. The ordering is forced by
the format (§7.1 steps 3-6: `kcTag` comes from `K` and is part of the header), Enigma.Core exposes only a
synchronous token-less `DeriveKey`, so the only remedy is `Task.Run` inside library code — the
async-over-sync antipattern the candidate itself said must not be done silently — and
`docs/guides/password-based.md:279` already calls it "a fixed prelude". The un-cancellable window is
Enigma.Core's tokenless KDF, not this library's statement order.

**R03 — "The unwrap and decapsulation messages blame the caller's key and omit the container-side cause."**
(C13, refuted 3/3.) The reproduction refuted rather than supported it: the two ML-KEM messages already name
"the container's parameter-set byte" (saying it "claims", which flags it as possibly false), and the RSA-half
message's `InnerException` names corruption explicitly, in exactly the place §9 designates as where "the
specific cause stays readable". §9 constrains exception **types**, and its only references to message text
are instructions *not* to rely on it. The candidate also cross-wired the two block quotes: the
"argument error for a tampered file" reasoning governs the ML-KEM row alone, while the RSA/hybrid unwrap is
governed by the block quote enumerating three **credential-side** causes — which is what the hybrid message
says. The claimed internal inconsistency dissolves: `0x03` names the OAEP-hash byte because `0x03` alone
*has* one, the hybrid's wrap being fixed at SHA-256 by deliberate design.

**R04 — "netstandard2.0's `FixedTimeEquals` omits `[MethodImpl(NoOptimization | NoInlining)]`."** (C15,
refuted 3/3.) The annotation is genuinely absent and .NET's own implementation does carry it, but nothing
here is a defect. The fallback loop is already branch-free with no early return; the only failure mode is a
hypothetical future optimiser the candidate conceded no shipping runtime performs; the sole call site
(`KeyConfirmation.Verify`) sits immediately after 600,000 PBKDF2 iterations or 64 MiB of Argon2id plus two
HMACs, whose millisecond-scale jitter swamps any nanosecond variation in a 16-byte loop; what would leak is
the position of a differing byte in a tag §6.3 already concedes any container holder can compute offline;
and on the AOT target named as most plausible (Unity IL2CPP) `[MethodImpl(NoOptimization)]` is a JIT hint
the emitted C++ never sees, so neither the leak nor the fix is reachable. The XML remarks describe exactly
the accumulator the code contains rather than promising a compiler barrier, so §6.2's "constant-time
comparison" is satisfied as written. Copying the attribute is reasonable hygiene, not a defect.

**R05 — "`docs/format.md` states no nonce or salt uniqueness requirement."** (C17, refuted 3/3.) The central
premise is a misreading. §7.1 step 2 — "Generate the salt (16 bytes), the GCM nonce (12 bytes) … from
`IRandomSource`" — is not an aside but a numbered step of the spec's **normative** Canonical operation
order, the same section §5 leans on for its non-circularity argument and §9 cites as authority ("the RSA
unwrap runs first (§7.2 step 4)"); step 3 likewise says "freshly generated `K`". GCM's own (key, nonce)
uniqueness rule comes with the cited mode rather than needing restatement. The document also scopes
third-party conformance to **readers** (§1.1 "a hand-written reader in another language", §10 "a conforming
reader … rejects both"), so there is no writer profile the omission could weaken. What remains is a request
for the word "MUST" plus a rationale paragraph. *(The uniqueness arithmetic the verifiers worked out is worth
recording: each data key is used for exactly **one** GCM invocation in every method, so SP 800-38D §8.3's
2^32-per-key random-IV budget is met with 2^32 margin, and for a reused password a (key, nonce) repeat needs
both a 128-bit salt collision and a 96-bit nonce collision on the same pair — ~2^112 containers, not the
~2^48 a naive reading of a 96-bit nonce suggests.)*

**R06 — "§6.3's 'the construction is key-committing' overstates a 128-bit truncated tag."** (C18, refuted
3/3.) §6.3 makes no quantitative claim; the "128-bit second-preimage level" was the candidate's own
inference. The paragraph's content is a qualitative contrast with plain GCM — where a two-key ciphertext is
*cheaply constructible* — which stays true at a ~2^64 generic search. The 16-byte truncation a reviewer
would need is stated three times in the same contract: §4's two fixed-parameter rows, §6's `[0..16]`
formula bullet ("the leftmost 16 bytes of the 32-byte HMAC output"), and the XML doc on
`KeyConfirmationTagSizeBytes`. Tag-based commitment at 128-bit tags is called committing throughout the
literature (CTX, Ascon, AEGIS). The requested change is prose polish.

**R07 — "The clearing guarantee is narrower than it reads; the RSA private key is an unclearable
`string`."** (C20, refuted 3/3.) Both halves fail on the facts. The interface remarks are already precisely
scoped — "the data key and the key-confirmation key derived internally are cleared before returning; the
caller-supplied `password` is not" — matching §7.1 step 8 and §7.2 step 7 exactly, and nowhere claiming no
copy survives the process. The `string`-PEM asymmetry is **already documented verbatim** at
`docs/guides/rsa.md:404-406` ("PEM text is a `string`, and strings are not clearable… an encrypted
private-key PEM plus a `char[]` passphrase keeps the sensitive part in an array you *can* clear"), and the
`string` is imposed by Enigma.Core's `DecryptOaep(..., string privateKeyPem, ...)` signature rather than
chosen here. The residue — that a wrapper cannot reach a BouncyCastle primitive's key schedule — is exactly
the platform-limitation restatement the audit brief refutes on principle, and its failure scenario needs an
adversary already reading process memory who at that moment also holds the plaintext, the live password
array and the PEM string.

---

# Coverage statement — PHASE01

## What was examined

Read in full, line by line, by at least one finder and usually several: all six services and their six
interfaces under `Services/`; all fifteen files under `Internal/`; all three files under `Exceptions/`;
`DataEncryptionDefaults.cs`; `DataEncryptionLimits.cs`; `ServiceCollectionExtensions.cs`;
`Properties/AssemblyInfo.cs`; and `docs/format.md` §§1-10 including all three §9 block quotes.
`DataEncryptionFileExtensions.cs` and `CLAUDE.md` were read as supporting evidence. Consulted as evidence:
`RsaFailureTests`, `HybridFailureTests`, `HybridArgumentValidationTests`, `HybridKeyCombinerTests`,
`HybridKeyFixture`, `RsaKeyFixture`, `MLKemFailureTests`, `PasswordFailureTests`,
`PasswordArgumentValidationTests`, `PasswordCancellationTests`, `LimitsValidatorTests`,
`HeaderValidationTests`, `HeaderTruncationTests`, `HeaderGoldenBytesTests`, `FormatLayoutTests`,
`GoldenVectorPrimitives`, `MalformedContainerSweepTests`, `DataEncryptionFileExtensionsTests`,
`RandomSourceTests`, `TestStreams`, plus a directory-level scan of the remaining test files.

**Dependency behaviour was settled by decompilation, not intuition**, wherever a conclusion turned on it
(`ilspycmd` against the shipped NuGet assemblies): Enigma.Core's `RandomUtils` on **all three TFMs**
(byte-identical), `BlockCipherService`, `PublicKeyService` (all members plus its private `Transform`),
`PemUtils`, `MLKemService`, `Argon2Service`, `StreamExtensionsBytes`, `StreamExtensionsLengthValue`,
`StreamReadHelpers`; and from BouncyCastle 2.6.2: `SecureRandom`, `DigestRandomGenerator`,
`CryptoApiRandomGenerator`, `CryptoServicesRegistrar`, `GcmBlockCipher`, `MLKemEncapsulator`,
`MLKemDecapsulator`, `Argon2BytesGenerator`, `OaepEncoding`, `CipherStream`.

**Reproduced by execution** (13 probes by the lead plus independent harnesses per verifier, all in the
session scratchpad, none committed): the hybrid wrap-failure escape; the RUP threshold by payload size;
the synchronous-throw/faulted-task matrix; hostile-header Argon2 and PBKDF2 cost; cancellation during a
KDF; a throwing `IProgress`; the inspector on an edited selector byte; `HeaderReader`'s catch breadth
against a failing caller stream; the synchronous-KDF measurement, isolated with a guaranteed-yielding
stream; the `inputPath == outputPath` deletion; RFC 9106's first recommended option failing default-limits
decrypt; `m < 8p` against the reference `argon2` CLI; the 68.7 GB GCM block-cap boundary; and the
`RandomSource` state-restoration demonstration of (key, nonce) reuse.

## Verified clean — attacked and found sound

Recorded so a later reviewer need not redo the work.

- **The hybrid key combiner.** Each secret is genuinely the HMAC **key** and never appears in a message
  (Enigma.Core's `ComputeHmac(data, key)` argument order is correct at all three call sites). The two
  labels differ, are exactly 35 and 37 ASCII bytes, and match §3.5.1's hex byte-for-byte. `BuildTranscript`
  emits `LE32(N) ‖ wrapped ‖ LE32(M) ‖ encap` with a correct little-endian writer, byte-identical to the
  header slice `[18, 26+N+M)`. `K` is bound to both ciphertexts. Concrete attacks were attempted and none
  work: forcing `K = 0` needs `Krsa == Kkem`, blocked by the distinct labels; a hostile sender grinding
  toward a chosen `K` is a 2^256 search over a PRF output; an adversary holding one private key learns only
  that branch; and HMAC's short-key zero-padding equivalence — the one degenerate case a hostile sender
  could otherwise reach — is closed by the `rsaSecret.Length != 32` guard.
- **The tests do prove both hybrid inputs contribute**, and the suite is honest about why a "wrong RSA
  private key" test would not have (OAEP rejects before the combiner runs), supplying hostile-sender
  containers instead.
- **Key confirmation.** `kcKey` derivation, the exact 27-byte ASCII label, truncation to the **leftmost**
  16 bytes, and verification before any payload byte in **all five** methods, with
  `PayloadWasRead == false` asserted in each case.
- **The `kcTag`/AAD ordering is not circular** — §5's numbered argument holds as written. The
  circularity a verifier is warned to expect was looked for and not found.
- **The AAD is the tee-ed wire bytes.** `TeeStream` mirrors only bytes actually returned, never reads
  ahead, and `BytesBeforeTag` matches the writer's `beforeTag`. Cross-method reinterpretation attacks
  (editing the method byte to make the reader misparse the shape) degrade to a 128-bit MAC-forgery oracle
  under an unknown `kcKey` and yield no new capability.
- **Limits before work.** The comment at `HeaderReader.cs:215-217` is accurate:
  `ReadLengthValueAsync` checks its cap before `new byte[count]`, on all three length-value reads.
  Worst-case **allocation** for a default-limits reader is ~8.2 KB.
- **§7.1/§7.2 ordering, all five methods**, step by step: validation before generation, generation before
  derivation/wrap/encapsulation, every public-key operation before the header build and therefore before
  every write, the combiner before the header, the tag over the pre-tag bytes, the AAD tag-inclusive, and
  on decrypt the hybrid unwrapping before decapsulating.
- **Key-material clearing.** Every data key, `kcKey`, intermediate MAC, hybrid input secret and combiner
  branch is cleared in a `finally` enclosing all uses — including the two wrapped-length-mismatch
  rejection paths, the cancelled-operation path, the failed-header-write path and the `char[]` password
  buffers.
- **No translation anywhere distinguishes causes by message text** (`grep -rn "\.Message" src/` returns
  nothing).
- **§9's table was diffed row by row against the code for all five methods, both directions.** Every row
  is honoured except F04's. `InnerException` is preserved at every site where §9 says "wrapping it".
- **ML-KEM implicit rejection** is proved against Enigma.Core directly and is consistent with FIPS 203
  Alg. 18; the tag catches the wrong key before any payload byte, for both `0x04` and `0x05`.
- **The RNG test seam is unreachable in production.** Every public constructor chains to
  `new RandomSource()`; `IRandomSource` is internal, and a foreign assembly cannot implement it without
  `IgnoresAccessChecksTo`. Deliberate choice 10 holds. `RandomUtils`' `((Random)secureRandom).NextBytes`
  cast is safe — `SecureRandom` overrides `Random.NextBytes(byte[])`, so it dispatches to the generator
  and not to `Random`'s LCG (checked explicitly, since a missing override would have been catastrophic).
- **No derived value is used as a nonce.** All seven `GenerateRandomBytes` call sites were traced; every
  nonce is 12 fresh bytes, and on decrypt the nonce is read from the header and passed through unmodified.
- **The inspector** raises the format half alone and reports an edited-but-valid cipher byte as it found
  it, exactly as §9's closing paragraph promises (reproduced).
- **Default cost parameters** match §4.1 and RFC 9106's second recommended option (t=3, m=64 MiB, p=4,
  Argon2id, version 1.3, 32-byte output, 16-byte salt); PBKDF2's 600,000 is the OWASP figure the docs
  cite.

## What PHASE01 consciously did not examine

- **Header offsets, sizes and golden-vector byte values** — PHASE02's dimension. `FormatLayout`'s
  arithmetic was checked only far enough to confirm `38 + N == 38 + N` and `42 + N + M`.
- **Golden-vector provenance and fixture correctness**, and whether `GoldenVectorInventoryTests` matches
  what is committed — PHASE03's dimension.
- **Coverage measurement.** PHASE01 collected none; PHASE03 owns it, and must measure at the audited
  commit rather than reuse the pre-dependency figures.
- **Mutation probing** — PHASE03's carve-out. No `src/` file was mutated in PHASE01.
- **The malformed-input truncation sweep and header-parse edge cases in detail**; the thread-safety and DI
  suites; the BouncyCastle and internal-surface isolation guards.
- **The remaining ten file-path extension methods** beyond the PBKDF2 quartet and the shared `RunAsync`
  plumbing.
- **Packaging, csproj, `global.json`, `.editorconfig`, the guides as documents, and the `netstandard2.0`
  polyfill surface** — PHASE04's dimension. F04's guide error and O04's stale XML comments are forwarded
  there.
- **The primitive implementations inside Enigma.Core and BouncyCastle** beyond the randomness, GCM-limit,
  Argon2-clamp and exception-filter questions the findings turned on. This audit assumes the primitives
  are correct; it audits only the container and its use of them.
- **`netstandard2.0` timing behaviour was reasoned about, not measured.** R04's conclusion rests on the
  absence of any shipping runtime that performs the transformation, not on a timing experiment on
  .NET Framework, Mono or IL2CPP.
- **F07's 68.7 GB boundary was reproduced once, on one platform**, and no fixture of that size exists or
  should.

## Execution boundary

No file outside `docs/review/`, `docs/roadmap.md`, `docs/plan/` and `docs/done/` was created, modified or
deleted. No `src/` file was mutated, even temporarily. All verification code lives in the session
scratchpad and is quoted here rather than committed; no test was added to the suite. `git diff --stat`
against the phase branch point is recorded in `docs/done/FEATURE-F612-PHASE01.md`.
---

# PHASE02 — `docs/format.md` conformance

**Date:** 2026-07-29
**Commit reviewed:** `e36df1ecd36723bb4d179243a84168a8b7b1d50e` (branch
`feature/feature-f612-phase01-crypto`, at the merge of PHASE01's report). The audited *library* code is
unchanged from PHASE01's `b1ab2c2`: `e36df1e` adds only `docs/review/FEATURE-F612.md` and the two
workflow artifacts, so PHASE01's baseline stands (acceptance criterion 7) and PHASE02 re-ran no suite.
**Dimension:** conformance between `docs/format.md` and the code, **in both directions** — a spec clause
the code does not honour, *and* a behaviour the code has that the spec does not license.

## Scope

`docs/format.md` §§1.1, 1.2, 2–2.4, 3.1–3.5.2, 4, 4.1, 5, 6–6.3, 7.1, 7.2, 8, 9, 10, checked against
`Internal/` (`FormatLayout`, `HeaderWriter`, `HeaderReader`, `MLKemParameterSetWire`, `RsaOaepHashWire`,
`CipherResolver`, `LimitsValidator`, `ParsedHeader`, `HybridKeyCombiner`, `KeyConfirmation`,
`PayloadCipher`), `EncryptedDataHeader.cs`, `Cipher.cs`, `EncryptionMethod.cs`,
`DataEncryptionDefaults.cs`, `DataEncryptionLimits.cs` and `Api/FormatConstantsTests.cs`. The five
services, `EncryptedDataInspector` and the committed fixtures were read as far as §5, §7.1, §7.2 and §9
conformance required.

## Method

Same shape as PHASE01, per `docs/plan/FEATURE-F612.md` §*Method*.

1. **Find.** Ten dimension-specific finder sub-agents, each with fresh context over a defined slice:
   §1.1 integer encoding and endianness · the two password shapes · method `0x03` post-`FEATURE-0D64` ·
   methods `0x04`/`0x05` post-`FEATURE-5A30` · §4/§4.1/§6/§8 constants · §5 and the §7.1/§7.2 operation
   order · the rejection matrix and the inspector's §9 guarantee · what `FormatConstantsTests` actually
   pins · error messages and XML docs as contract · and one finder assigned the **reverse direction
   only**, which wrote two independent spec-only readers (a Python header parser and a BCL-only C#
   decryptor) plus a spec-only *writer*, and ran them against all fourteen committed fixtures. Every
   finder was primed with the eleven documented deliberate choices, with PHASE01's *verified clean* list
   so it would not be redone, and with PHASE01's ten admitted findings so they would not be re-reported.
   **32 candidates.**
2. **Deduplicate.** 32 candidates → **18 distinct claims** (C01 raised independently by 4 of 10 finders;
   C02–C07 by 2 each), plus **5 finder-proposed Observations routed straight to the Observations section
   without refutation**, on PHASE01's O04/O05 precedent.
3. **Refute.** Each of the 18 went to **three independent verifier sub-agents with distinct lenses** —
   *correctness*, *spec authority*, *reproducibility* — each instructed to **default to refuted when
   uncertain**, and each given the audit lead's own independently established facts so it would not
   re-derive them. **54 verifiers.**
4. **Admit.** **9 admitted, 9 refuted.**

**Two guards were set deliberately, and both fired.** C01 — encrypt-side cost parameters bounded only at
`> 0` — is the claim 4 of 10 finders raised and one proposed at High; it is also a re-dressing of
PHASE01's **O01**, which PHASE01 had already refuted down to an Observation. Its three verifiers were
handed PHASE01's verbatim refutation reasoning and told that re-admitting a PHASE01 observation on a new
argument that does not hold would be a real failure of this audit. They refuted it **3 of 3**. C14 was
likewise refuted as a **duplicate of PHASE01's F05**. Severity on each admitted finding is the **median
of its three verifiers' independent opinions**, not the finder's proposal.

## Result

**2 Medium, 7 Low. No Critical, no High.** The one candidate proposed at High (C08) was reproduced
independently by all three of its verifiers and settled unanimously at Medium; the other High proposal
(part of C01) was refuted outright.

The two Mediums are the only findings with a consequence beyond prose. **F11** is an untranslated
`IndexOutOfRangeException` escaping `DecryptAsync` for a tampered container — the exact class of failure
the malformed-input sweep asserts against by name, missed only because the sweep's RSA harness uses a
2048-bit key. **F12** is a genuine hole in the contract: §3.3 pins RSAES-OAEP's hash but neither its
mask-generation function nor its label, so a third-party writer following every statement the document
actually makes can produce containers this library rejects.

The remaining seven are documentation and pinning defects, five of which are **shipped public XML** or
**the normative spec contradicting itself** rather than internal notes.

---

# Findings — PHASE02

Continuing PHASE01's numbering. Ordered Critical → High → Medium → Low. Each carries a severity, a
`file:line`, a concrete failure scenario, a recommended fix, and a refutation record listing all three
verifiers' lens, verdict and one-line reasoning, followed by the strongest surviving counter-argument.

---

## Medium

### F11 — A tampered method `0x03` container built with a small RSA modulus throws an unwrapped `IndexOutOfRangeException` out of `DecryptAsync`, which §9 forbids and the malformed-input sweep asserts against by name

**Severity:** Medium (verifier opinions: Medium / Medium / Medium) · **Candidate:** C08 · survived 3 of 3
**Location:** `src/Enigma.DataEncryption/Services/RsaDataEncryptionService.cs:300-310` (the `catch` is `CryptographicException`-only); `src/Enigma.DataEncryption/Internal/HeaderReader.cs:209-210` (offset 5 accepted with no cross-check against `N`); `docs/format.md:196-198` (§3.3) and `docs/format.md:565` (§9)

**What is wrong.** §3.3 asserts that an edited offset-5 byte needs no rule of its own, because it always
surfaces as an OAEP unwrap failure that §9 already maps to `DataDecryptionException`:

> **A reader takes the hash from the header, never from its caller.** … An edited byte therefore makes
> the OAEP unwrap fail, which §9 already covers — it needs no rule of its own.

That holds only while the modulus is large enough for BouncyCastle's OAEP *decoder*. Below the decoder's
bound, `OaepEncoding.DecodeBlock` indexes past the end of its working array and raises
`System.IndexOutOfRangeException`. Two verifiers independently established the exact condition, correcting
the finder's arithmetic in the process: the decoder over-reads whenever
`RsaCoreEngine.GetOutputBlockSize()` — which is `(modBits − 1) / 8` — is **less than `2·hLen`**, i.e. less
than 128 for SHA-512. Pinned by execution: 1,016 bits and 1,024 bits throw; 1,032 bits and above do not. That is not a BouncyCastle `CryptoException`, so Enigma.Core's
`PublicKeyService.Transform` — which translates the `CryptoException` hierarchy and nothing else — does
not convert it; so `UnwrapDataKey`'s `catch (CryptographicException)` does not see it; so it escapes
`DecryptAsync` and `DecryptFileAsync` untranslated.

The affected window is **k ∈ [98, 128] bytes** — bounded below by the 98 bytes RFC 8017 needs to have
written the container under the default SHA-256, and above by the decoder bound. That window is *exactly*
RSA-1024 and below, and RSA-1024 is not a size the library disowns: `IRsaDataEncryptionService.cs:66-67`
says "RSA-2048 and above satisfy all three; RSA-1024 satisfies only SHA-256", `docs/guides/rsa.md:185`
repeats it, and `RsaFailureTests.RsaTenTwentyFourStillWorksUnderTheDefaultHash` asserts a full RSA-1024
round trip succeeds.

**Failure scenario.** Alice encrypts for Bob with a legacy RSA-1024 key pair under the default
OAEP-SHA-256; the library accepts this and writes a valid `38 + 128 = 166`-byte header. An attacker, or a
corrupting transport, changes the single byte at offset 5 from `0x02` to `0x04`. Bob calls `DecryptAsync`
inside the `catch (DataEncryptionException)` block that §9 and the shipped XML docs tell him is
sufficient. He gets `System.IndexOutOfRangeException` instead — unhandled, and saying nothing about the
container being corrupt. In a service host processing untrusted files, that is an unhandled-exception
crash on a merely tampered input.

**Why the green suite misses it.** Not because the invariant is unstated —
`MalformedContainerSweepTests.cs:470` asserts `IsNotType<IndexOutOfRangeException>` **verbatim**, and
`AnEditedRsaOaepHashByteIsAContainerError` sweeps exactly this byte. It misses because the harness builds
its RSA container from the committed 2048-bit fixture
(`ContainerMethodHarness.cs:415` → `RsaTestData.GoldenPublicKeyPem()` → `Fixtures/rsa-2048-public.pem`),
where k = 256 is comfortably above the decoder bound and all 255 foreign bytes surface as container
exceptions.

**Recommended fix.** Change the code, not the spec, and prefer the format-level check: reject in
`HeaderReader.ReadRsaBodyAsync` any container whose wrapped-key length `N` is below the minimum a legal
OAEP wrap under the hash named at offset 5 could have produced. That is derivable from data already in
the header, costs nothing, keeps §9's causes distinct, and correctly classifies as
`DataEncryptionFormatException` a header that cannot describe a legal wrap. The broader alternative —
widening `UnwrapDataKey`'s translation to catch any non-cancellation exception out of `DecryptOaep`
other than the deliberately-propagated PEM-parse cases — also closes PHASE01's **F04** and should be
considered alongside it. Then extend the sweep's RSA harness to one sub-2048 modulus, which is what would
have caught this.

**Corrections applied during refutation.**
- *(correctness lens)* The finder's BouncyCastle arithmetic is wrong in detail, though its
  conclusion and window are right. BC's `RsaCoreEngine.GetOutputBlockSize()` returns `(bitSize - 1) /
  8` in the decrypt direction — 127 bytes for RSA-1024, not 128 — so `DecodeBlock`'s working array is
  127 bytes. The first over-read is not the `2*hLen+1` seed/length scan the finder names but the
  defHash comparison loop `num |= defHash[i] ^ array[defHash.Length + i]` at i = hLen-1, i.e. index
  2*hLen-1 = 127 into a 127-byte array. The true requirement is block >= 2*hLen = 128, hence k >= 129,
  not "129 bytes needed, 128 available". Verified empirically: RSA-1025 (k=129) does NOT escape,
  RSA-1024 (k=128) does, so the finder's stated window k in [98,128] is nevertheless exactly correct,
  and I confirmed both ends of it (RSA-776 is refused at encrypt time with the documented
  ArgumentException; RSA-784, k=98, escapes). Also confirmed the finder's negative claim: byte5=0x03
  (SHA-384) never escapes at any size tested, and the escape is limited to 0x04. Everything else in
  the claim — the location, the catch clauses, the stack, the sweep's blind spot — reproduces exactly
  as stated.
- *(spec authority lens)* Three corrections. (1) MECHANISM/THRESHOLD: the finder says
  OaepEncoding.DecodeBlock "indexes into the recovered block assuming at least 2·hLen+1 bytes; with
  hLen=64 that is 129 bytes, and an RSA-1024 modulus gives it 128." Both numbers are wrong.
  Decompiling BouncyCastle.Cryptography 2.6.2 shows the over-read is in the trailing loop `for (int j
  = 2 * defHash.Length; j != array.Length; j++)`, where `array.Length == engine.GetOutputBlockSize()
  == (modBits - 1) / 8` — the RSA *output block* size, which is k-1 for a byte-aligned modulus, not k.
  The loop walks off the end whenever that value is strictly less than 2·hLen (= 128 for SHA-512), not
  2·hLen+1. I pinned the boundary by execution: 1016 bits (obs=126) and 1024 bits (obs=127) throw
  IndexOutOfRangeException; 1032 bits (obs=128) and 1040 bits (obs=129) correctly throw
  DataDecryptionException. So the true condition is (modBits-1)/8 < 2·hLen, and the byte-aligned
  window k ∈ [98,128] the finder quotes happens to come out right by coincidence rather than from the
  arithmetic they gave. (2) TEST-SUITE CLAIM: the finder writes "grep -rn \"1024\" tests/ returns no
  RSA key size, only ML-KEM-1024." That is false. tests/.../Services/RsaKeyFixture.cs:46 generates a
  1024-bit RSA pair (and :49 a 512-bit one), RsaFailureTests.cs:544-550
  (`RsaTenTwentyFourStillWorksUnderTheDefaultHash`) asserts a full RSA-1024 encrypt/decrypt round trip
  succeeds, and RsaFailureTests.cs:509-520 pins that RSA-1024 + SHA-384/512 is an ArgumentException on
  encrypt. This correction strengthens the claim rather than weakening it: the suite deliberately
  blesses the exact key size where the decrypt-side gap lives. (3) SWEEP-MISS REASON, confirmed
  precisely: MalformedContainerSweepTests.AnEditedRsaOaepHashByteIsAContainerError does sweep all 255
  foreign values of the offset-5 byte, but its container comes from ContainerMethodHarness's
  RsaHarness, which hardcodes RsaTestData.GoldenPublicKeyPem() (ContainerMethodHarness.cs:415) = the
  committed rsa-2048-public.pem, k=256, obs=255 — comfortably above 128 for every accepted hash. The
  sweep is structurally incapable of reaching the window. Also note SHA-384 genuinely cannot trigger
  it (2·48=96, and the SHA-256 wrap already forces k>=98, obs>=97), so the finder is right that this
  is invisible to inspection of §3.3's wrap bound 2·hLen+34; and the hybrid 0x05 is correctly out of
  scope, since its wrap is fixed at SHA-256 (2·32=64, and obs>=97 always).
- *(reproducibility lens)* Two corrections to the finder's evidence, both of which I established
  myself. (1) The finder writes: "Why the existing suite misses it: … `grep -rn \"1024\" tests/`
  returns no RSA key size, only ML-KEM-1024." That is FALSE.
  tests/Enigma.DataEncryption.UnitTests/Services/RsaKeyFixture.cs:46 does `(PublicKeyPem1024,
  PrivateKeyPem1024) = service.GenerateRsaKeyPair(1024);`, RsaKeyFixture.cs:77-82 documents the pair
  as "usable under OAEP-SHA-256, too small for SHA-384 and SHA-512", and RsaFailureTests.cs:537-542
  has a test named `RsaTenTwentyFourStillWorksUnderTheDefaultHash` whose own doc comment says
  "RSA-1024 still works under SHA-256". The suite therefore knows about and blesses RSA-1024 — which
  strengthens rather than weakens the claim. The correct reason the malformed sweep misses the defect
  is narrower and I verified it: MalformedContainerSweepTests.AnEditedRsaOaepHashByteIsAContainerError
  calls ContainerAsync(ContainerMethodKind.Rsa), whose harness (ContainerMethodHarness.cs:415)
  encrypts with RsaTestData.GoldenPublicKeyPem(), which RsaTestData.cs:141 resolves to the committed
  Fixtures/rsa-2048-public.pem — k=256, comfortably above the 129-byte decoder bound, so all 255
  foreign bytes surface as container exceptions there. (2) The finder's failure-scenario line
  "produces a valid 38+N=166-byte-header container" is right about the header (38+128=166) but the
  finder's probe labels are container-payload sizes; my RSA-1024 container over a 200-byte plaintext
  is 382 bytes total. Nothing else in the finder's mechanism needed correcting: the 2·hLen+1 =
  129-byte DecodeBlock bound, the [98,128] window, the SHA-384 non-triggering (2·48+1 = 97 <= 98), the
  Enigma.Core PublicKeyService.Transform CryptoException-only translation, and both source citations
  (RsaDataEncryptionService.cs:300-310, HeaderReader.cs:209-210) all check out verbatim against my run
  and the files.

**Refutation record.**
- **correctness — not refuted:** "I independently generated RSA keys at
  776/784/792/1024/1025/1032/2048 bits with OpenSSL, encrypted real containers through the shipped
  Release `RsaDataEncryptionService` under the default OAEP-SHA-256, and swept byte 5 over all 256
  values: for every modulus of 98–128 bytes (RSA-784 through RSA-1024 — all of which the library,
  `docs/format.md` §3.3 and `docs/guides/rsa.md`:185 explicitly bless for SHA-256) editing offset 5 to
  `0x04` (SHA-512) makes `DecryptAsync` throw an unwrapped `System.IndexOutOfRangeException` out of
  `OaepEncoding.DecodeBlock`, because `PublicKeyService.Transform` translates only BouncyCastle's
  `CryptoException` and `RsaDataEncryptionService.UnwrapDataKey`
  (`src/Enigma.DataEncryption/Services/RsaDataEncryptionService.cs:302`) catches only
  `CryptographicException` — so §3.3's "an edited byte therefore makes the OAEP unwrap fail, which §9
  already covers — it needs no rule of its own" and §9's "the exception a reader raises is part of the
  contract" are both broken, and PHASE05's malformed-input sweep misses it purely because `RsaHarness`
  builds its container from the committed RSA-2048 fixture (`ContainerMethodHarness.cs:415` →
  `RsaTestData.GoldenPublicKeyPem()`), where k=256 is comfortably above the decoder bound."
- **spec authority — not refuted:** "I reproduced the defect from scratch with my own probe against
  the prebuilt Release DLL — generating fresh RSA key pairs, encrypting real method-0x03 containers
  under the default OAEP-SHA-256, flipping the single byte at offset 5 to 0x04 and sweeping all 256
  values at six modulus sizes — and confirmed that at 800/1016/1024 bits a raw
  System.IndexOutOfRangeException escapes both DecryptAsync and DecryptFileAsync while 1032 bits and
  above correctly raise DataDecryptionException; docs/format.md §9 opens "The exception a reader
  raises is part of the contract" and §3.3 asserts unconditionally that an edited offset-5 byte "makes
  the OAEP unwrap fail, which §9 already covers — it needs no rule of its own", nothing in §4, §9 or
  §10 licenses an untranslated indexing failure, the malformed-input sweep misses it only because its
  RSA harness always uses the committed 2048-bit rsa-2048-public.pem (ContainerMethodHarness.cs:415),
  and RSA-1024 is not an exotic key size the library disowns but one its own suite generates and
  round-trips successfully (RsaKeyFixture.cs:46, RsaFailureTests.cs:546-549), so the claim stands —
  though the finder's arithmetic and their "grep finds no RSA-1024 in tests" remark are both wrong."
- **reproducibility — not refuted:** "I built a standalone probe against the prebuilt Release DLL
  that generates real method-0x03 containers at moduli k=98,99,127,128,129,130,136,160,192,256 bytes
  under the default OAEP-SHA-256, verifies a clean round-trip, then sweeps the offset-5 byte over all
  256 values, and it reproduces the claim exactly: for every k in [98,128] the single edit byte5=0x04
  (SHA-512) escapes DecryptAsync as System.IndexOutOfRangeException thrown inside
  Org.BouncyCastle.Crypto.Encodings.OaepEncoding.DecodeBlock and passed straight through
  RsaDataEncryptionService.UnwrapDataKey's `catch (CryptographicException)` at line 305, while at
  k=129 and above nothing escapes and byte5=0x03 (SHA-384) never escapes at any size — so §3.3's "An
  edited byte therefore makes the OAEP unwrap fail, which §9 already covers — it needs no rule of its
  own" and §9's "The exception a reader raises is part of the contract" are both falsified for
  RSA-1024, a key size the shipped XML docs, docs/guides/rsa.md:185-189 and
  RsaFailureTests.RsaTenTwentyFourStillWorksUnderTheDefaultHash all explicitly bless under SHA-256,
  and PHASE05's sweep misses it only because ContainerMethodHarness.cs:415 builds its RSA container
  from the committed rsa-2048-public.pem (k=256), not because the invariant is unstated —
  MalformedContainerSweepTests.cs:470 asserts IsNotType&lt;IndexOutOfRangeException&gt; verbatim."

**Strongest surviving counter-argument.** The strongest case against: §9's row is written as "RSA
OAEP unwrap failure, including an undecryptable private-key PEM (`CryptographicException`)" — the
parenthetical arguably *scopes* the row to CryptographicException, so an IndexOutOfRangeException is
simply a condition the table never claimed to map, making this an unlisted third-party-library bug
rather than a broken normative clause. Reinforcing that: the actual fault is in BouncyCastle 2.6.2's
own constant-time DecodeBlock, which computes its `wrongMask` correctly and then over-reads before
consulting it — Enigma.DataEncryption's `catch (CryptographicException)` is faithfully translating
exactly what Enigma.Core's documented contract emits, and no amount of reading docs/format.md would
have predicted an upstream indexing bug. Scope narrows it further: the window is deprecated moduli
of at most 1031 bits, a size no committed fixture, no guide snippet and no realistic 2026 deployment
uses; it needs a deliberate one-byte edit of a field only tampering or corruption would touch; and
the outcome is an exception of the wrong *type* — no plaintext or key is exposed, no container is
silently mis-decrypted, no wrong bytes are produced or accepted. Under my own lens's rubric, no
third-party implementer coding from docs/format.md is misled: §3.3 tells them to map an edited
offset-5 byte to a decryption error, and a reader that does so is correct — this library is the only
one that gets it wrong, which is an implementation bug, not a spec defect, and arguably belongs in
an upstream issue rather than a conformance finding. I was not fully persuaded, because §3.3's
sentence "An edited byte therefore makes the OAEP unwrap fail, which §9 already covers — it needs no
rule of its own" is an unconditional factual assertion this library falsifies about itself, §9's
opening line "The exception a reader raises is part of the contract" is normative and unqualified,
CLAUDE.md states the sweep's guarantee as "never an indexing, allocation or unwrapped Enigma.Core
failure" and this is literally an indexing failure, and the finder's narrower fix (reject N <
2·hLen+34 for the hash named at offset 5, in HeaderReader.ReadRsaBodyAsync) is a pure header-
derivable check that needs no format-version bump, invalidates no committed fixture, and cannot
reject any legitimate container.

---

### F12 — §3.3 pins RSAES-OAEP's hash but neither its mask-generation function nor its label, so a writer conforming to every statement the document makes can produce containers this library rejects

**Severity:** Medium (verifier opinions: Medium / Medium / Medium) · **Candidate:** C09 · survived 3 of 3
**Location:** `docs/format.md:164` and `:167` (§3.3), `docs/format.md:359` (§4's wrapping row); `src/Enigma.DataEncryption/Services/RsaDataEncryptionService.cs:245-246` and `:300-310`

**What is wrong.** RSAES-OAEP takes three independent parameters: the hash, the mask-generation function,
and the label. `docs/format.md` states one of them. §3.3's table row says only "RSAES-OAEP with **the
selected hash**"; §4's row says only "RSAES-OAEP, SHA-256". `grep -i "mgf\|mask.gener\|pSource"` returns
**zero hits** across the whole of `docs/format.md`, `docs/guides/` and `src/`.

The code fixes MGF1 to the selected hash and the label to empty, by way of BouncyCastle's two-argument
`OaepEncoding(cipher, hash)` constructor, which chains to `(cipher, hash, hash, null)`. That is the right
choice and the conventional one — but it is a choice the contract never records.

This is not a hypothetical gap in a document that is otherwise loose. §4 is fine-grained enough to pin
"Argon2 version 1.3" and "GCM padding: none", and RFC 8017 — the standard §3.3 cites by name — makes
`maskGenAlgorithm` a free parameter whose **ASN.1 default is `mgf1SHA1`**. A third-party implementer
following the cited standard's own default therefore lands on the *incompatible* reading. The
"RECOMMENDED that the underlying hash function be the same" note a reader might lean on lives in RFC 8017
Appendix A.2.3, which is RSASSA-PSS, not A.2.1's RSAES-OAEP.

**Failure scenario.** An implementer writes a container generator in Java using the JCA transform name
`OAEPWithSHA-384AndMGF1Padding`, whose documented default MGF1 digest is SHA-1. Every byte the
specification actually states is correct: magic, method `0x03`, version `0x10`, hash byte `0x03` at
offset 5, nonce at 6, `N` at 18 as `Int32` LE, wrapped key at 22, a correct §6 `kcTag`, and a correct GCM
payload with the full header as AAD. This library rejects it with `DataDecryptionException` whose message
names three causes — a wrong private key, an undecryptable PEM, a corrupt container — **none of which is
the real one**. The implementer has no statement in the contract to check their work against.

**Recommended fix.** Change the spec. Add the two missing parameters to §3.3's wrapping description and
to §4's row: RSAES-OAEP with MGF1 keyed by the **same** hash and an **empty label** (`pSourceAlgorithm`
absent / zero-length). This is a pure documentation change — the code already does exactly this and no
container changes — and it is free before publication.

**Corrections applied during refutation.**
- *(correctness lens)* Four corrections to the finder. (1) "Nothing in the repo pins them either …
  there is no test that would fail if Enigma.Core changed the MGF1 digest" is FALSE: the three
  committed RSA containers plus rsa-2048-private.pem are decrypted end-to-end by
  RsaGoldenVectorTests.TheCommittedFixtureDecryptsToTheExpectedPlaintext (and hybrid-aes.bin
  likewise), and their wrapped-key bytes were produced with MGF1=hash/empty label, so an MGF1 change
  in Enigma.Core would break the suite. What is true is that nothing pins them INDEPENDENTLY —
  RsaTestData.WrapOaep/UnwrapOaep (RsaTestData.cs:191, :204) both route back through Enigma.Core's own
  EncryptOaep/DecryptOaep, and IndependentHeader takes the wrapped-key bytes from the file rather than
  recomputing them, so the pin is a self-consistent regression, not a cross-implementation vector. (2)
  The finder's appeal to Enigma.Core's enum XML doc is half-right and actually cuts against the
  defence: only the Sha1 member says "OAEP using SHA-1 as the mask-generation and label hash"; the
  Sha256/Sha384/Sha512 members say merely "OAEP using SHA-nnn", so the one symbol §4:359 normatively
  cites (RsaOaepHash.Sha256) carries no MGF1 statement at all. (3) The label half of the claim is
  weaker than presented: an empty label IS the PKCS#1 v2.2 default (pSourceAlgorithm DEFAULT
  pSpecifiedEmpty), so a reader following RFC 8017 lands on the code's choice; only maskGenAlgorithm
  (DEFAULT mgf1SHA1) is a genuine divergence trap, and my probe confirms label="Enigma" was never a
  live risk beyond ordinary under-specification. (4) The title scopes the gap to §3.3, but it applies
  verbatim to method 0x05 through §4:359, where there is no header field at all — the finder relegates
  this to the recommended fix.
- *(spec authority lens)* Three corrections to the finder. (1) FALSE: "nothing in the repo pins them
  either — there is no test that would fail if Enigma.Core changed the MGF1 digest."
  RsaGoldenVectorTests.TheCommittedFixtureWrapsTheDocumentedDataKey (line 133) and
  TheCommittedFixtureDecryptsToTheExpectedPlaintext unwrap the *committed* fixture bytes (rsa-aes.bin,
  rsa-aes-sha384.bin, rsa-aes-sha512.bin) through Enigma.Core, so any dependency-side change to the
  MGF1 digest or the label would break them immediately. What the repo lacks is documentation of the
  parameters, not regression detection of them — which is the actual defect and leaves the claim
  intact. (2) The label leg of the claim is materially weaker than the finder presents it: RFC 8017
  A.2.1 gives pSourceAlgorithm the DEFAULT pSpecifiedEmpty ("The default label is an empty string"),
  so an implementer following the RFC's defaults gets the empty label right, and .NET/BC/JCA/Python
  all default to it. The MGF1 leg is the inverse and carries the claim on its own — the RFC's default
  there is MGF1-SHA-1, i.e. the exactly-wrong value. (3) The finder did not look at the two places in
  the document that come closest to covering this, so I checked them: docs/format.md:187 ("because no
  external system ever unwraps these keys") is scoped to the SHA-1 legacy-interop argument, not to
  third-party readers of this format, and §4's fixed-parameters table (:352-362) is the natural
  normative home for both parameters and omits them. Verified as stated: the §3.3 offset-22 row at
  docs/format.md:167, the §4 wrapping row at :359, Enigma.Core
  PublicKeyService.EncryptOaep/DecryptOaep both calling the 2-arg `new OaepEncoding(new RsaEngine(),
  CreateOaepDigest(hash))`, and BouncyCastle 2.6.2's chain `OaepEncoding(cipher, hash)` -> `(cipher,
  hash, null)` -> `(cipher, hash, hash, encodingParams)`, i.e. mgf1Hash := hash and lHash := Hash("").
- *(reproducibility lens)* (1) The finder's assertion that "there is no test that would fail if
  Enigma.Core changed the MGF1 digest" is FALSE.
  `RsaGoldenVectorTests.TheCommittedFixtureDecryptsToTheExpectedPlaintext` (line 175) and
  `TheCommittedFixtureWrapsTheDocumentedDataKey` (line 133) both unwrap the committed `rsa-aes.bin` /
  `rsa-aes-sha384.bin` / `rsa-aes-sha512.bin` fixtures, which were written with MGF1 = the selected
  hash; an MGF1 change in Enigma.Core would break them. The regression protection exists — it is just
  repo-internal and invisible to a third-party implementer, so the spec gap survives. (2) Line
  numbers: `EncryptOaep` is called at RsaDataEncryptionService.cs:254 and `DecryptOaep` at :303, not
  :245-246 / :302-303. (3) The finder's Part-A hex outputs (69D167…, E29429…, 163316…) are not
  reproducible verbatim — they came from freshly generated containers with a fresh key. Against the
  committed fixtures the recovered data key is the golden 000102…1E1F for all three hashes; the
  mechanism reproduces exactly, the literal bytes do not. (4) An additional point the finder did not
  make, which strengthens the claim: §3.3 itself cites RFC 8017 (for `k >= 2·hLen + 34`), and RFC
  8017's RSAES-OAEP-params default MGF is MGF1-SHA-1 — so a literal RFC-8017 reading of "RSAES-OAEP
  with the selected hash" points at precisely the wrong answer.

**Refutation record.**
- **correctness — not refuted:** "I tried to kill C09 and could not: `grep -i "mgf\|mask.gener"`
  returns zero hits across all of docs/format.md, docs/guides/ and src/, while §3.3:167 says only
  "RSAES-OAEP with **the selected hash**" and §4:359 only "RSAES-OAEP, SHA-256" — yet RFC 8017/PKCS#1
  v2.2 makes maskGenAlgorithm an independent parameter whose ASN.1 default is mgf1SHA1, and the code
  fixes MGF1 := the selected hash (BouncyCastle's 2-arg `OaepEncoding(cipher, hash)` chaining to
  `(cipher, hash, hash, null)`, which I decompiled, and which I confirmed on the wire by unwrapping
  the three committed fixtures rsa-aes{,-sha384,-sha512}.bin with .NET's
  `RSAEncryptionPadding.OaepSHA256/384/512` to the documented data key 00…1F); splicing into a real
  SHA-384 container a wrapped key produced with hash=SHA-384/MGF1=SHA-1 — a container byte-identical
  at every offset the spec actually states — makes this library reject it as `DataDecryptionException`
  with a message naming three causes, none of them MGF1, so a hand-written reader "in another
  language", which §1.1:38 explicitly contemplates, is left to guess a parameter the contract never
  states."
- **spec authority — not refuted:** "I tried to kill this claim on every lens route and could not:
  grepping docs/format.md and src/ for "MGF"/"maskGen"/"pSource" returns zero hits, so the MGF1 hash
  and the OAEP label appear nowhere in the contract; RFC 8017 (which I downloaded and read) makes both
  free parameters of RSAES-OAEP and DEFAULTS maskGenAlgorithm to mgf1SHA1 — the "RECOMMENDED that the
  underlying hash function be the same as hashAlgorithm" note the spec might have leaned on is in
  Appendix A.2.3 for RSASSA-PSS, not in A.2.1 for RSAES-OAEP — so following the cited standard's own
  default produces the incompatible reading rather than the library's; and I reproduced the
  consequence end-to-end at the public surface by splicing a MGF1-SHA-1 wrap of the same data key into
  the committed rsa-aes-sha384.bin fixture (same N=256, every spec-stated offset intact), which the
  library rejects with a DataDecryptionException naming three causes, none of them the real one, while
  the same bytes wrapped with MGF1-SHA-384 unwrap correctly — and §4, the document's own table of
  fixed non-header parameters, is fine-grained enough to pin "Argon2 version 1.3" and "GCM padding:
  none" yet omits OAEP's other two parameters entirely, so this is an internal inconsistency in the
  contract, not a style preference."
- **reproducibility — not refuted:** "I hand-built a complete method-0x03 container from
  docs/format.md alone — magic EC DE, method 0x03, version 0x10, cipher 0x01, hash byte at offset 5,
  12-byte nonce at 6, N=256 as Int32 LE at 18, the OAEP-wrapped 32-byte data key at 22, the §6 kcTag
  over bytes [0,22+N), and an AES-256-GCM payload with the full 294-byte header as AAD — and the
  library decrypted it successfully when I used MGF1 = the selected hash with an empty label, but
  threw `Enigma.DataEncryption.DataDecryptionException` ("the wrapped data key could not be
  recovered…") for the byte-identical-everywhere-else container built with MGF1-SHA-1, the JCA
  `OAEPWith…AndMGF1Padding` default, for both SHA-256 and SHA-384; since `grep -c "MGF"
  docs/format.md` returns 0 and neither §3.3's "RSAES-OAEP with the selected hash" (line 167) nor §4's
  "RSAES-OAEP, SHA-256" (line 359) states the mask-generation function or the empty label, the claim
  stands: a writer conforming to every statement the normative document actually makes can produce
  containers this library rejects."

**Strongest surviving counter-argument.** The strongest case against is that this is a documentation
gap with an empty victim set and a loud failure mode, which the rubric would place at Observation
rather than Medium. No container exists outside this repository, no second implementation exists or
is planned, and §3.3 itself asserts at line 187 that "no external system ever unwraps these keys" —
so the harmed population is entirely hypothetical. When it does fail it fails closed and
immediately, at the unwrap, before a payload byte is read: nothing is silently mis-decrypted and no
plaintext or credential leaks. Against that, MGF1-with-the-same-hash is the overwhelming convention
(.NET's RSAEncryptionPadding.CreateOaep, BouncyCastle's convenience constructor, Python's usual
idiom), so the "obvious" reading of "RSAES-OAEP with the selected hash" is in practice the right one
and only the SunJCE transform name misleads — arguably a defect in JCA's naming rather than in this
document. And a would-be third-party implementer has the committed fixtures in the same repository
as the spec, so the first thing they would run is rsa-aes.bin, and the mismatch surfaces in minutes.
I was not persuaded, for two reasons the counter does not answer: §1.1 and §10 make hand-written
readers in other languages the document's declared audience and it pins Int32 byte order in four
lines of C for exactly that reason, so "no one will ever implement this" is not a premise the
document is entitled to; and the parameter is genuinely free in the cited standard, whose own
default is the incompatible value, so the omission is not licensed by RFC 8017 the way the empty
label arguably is.

---

## Low

### F13 — The shipped public XML on the `Cipher` enum still calls the cipher byte "the only algorithmic degree of freedom the format offers", contradicting the two spec sections it cites

**Severity:** Low (verifier opinions: Low / Low / Low) · **Candidate:** C02 · survived 3 of 3
**Location:** `src/Enigma.DataEncryption/Cipher.cs:8-13` (esp. 9-10); shipped as `Enigma.DataEncryption.xml:15` for all three TFMs; contradicts `docs/format.md:106-109` (§2.4) and `docs/format.md:371-372` (§4)

**What is wrong.** `Cipher`'s remark says the cipher byte "is the only algorithmic degree of freedom the
format offers" and that "Everything else (key size, nonce size, tag size, key-derivation function and its
variant) is a fixed invariant of the format and is not header-selectable" — then points the reader at
"`docs/format.md` §2.4 and §4". Those are precisely the two sections `FEATURE-0D64` rewrote to say the
opposite: §2.4 now reads "one of only **two** algorithmic degrees of freedom the format offers — the
other being method `0x03`'s RSA-OAEP hash (§3.3)", and §4 "A container carries exactly **two**
algorithmic fields".

The mechanism is documented in the git history. `FEATURE-0D64`'s plan made non-self-contradiction an
acceptance criterion and enumerated the in-code XML docs to update, but that list is RSA-scoped;
`grep -n "Cipher.cs" docs/plan/FEATURE-0D64.md docs/done/FEATURE-0D64.md` returns nothing, and
`git show --stat 3443bcb` confirms the commit touched no cipher file. `Cipher.cs` has been untouched
since `FEATURE-00E7`.

**Failure scenario.** A caller under a policy mandating SHA-384 or SHA-512 for key transport — the exact
caller §3.3 says the field exists for — reads `Cipher`'s IntelliSense, is told the cipher is the only
algorithmic choice and that everything else is fixed, and concludes the library cannot meet their policy.
This is shipped IntelliSense, not an internal note: a verifier packed the library and found the sentence
at line 15 of `lib/net10.0`, `lib/net8.0` and `lib/netstandard2.0`'s `Enigma.DataEncryption.xml`.

**Recommended fix.** Change the code doc. Rewrite `Cipher`'s remark to say the cipher is one of two
header-selectable algorithmic fields, the other being method `0x03`'s OAEP hash, keeping the §2.4/§4
citation and the "no value is a downgrade of another" argument, which is still correct.

**Corrections applied during refutation.**
- *(correctness lens)* (1) Finder DIMENSION E overreaches in saying the sentence "Everything else …
  is not header-selectable" is "false for both of those bytes", counting the ML-KEM parameter set
  (offset 5, methods 0x04/0x05) as a further counterexample. §4 at docs/format.md:371-380 deliberately
  counts exactly TWO algorithmic fields and does not count the ML-KEM parameter set among them; and
  Cipher.cs's "Everything else" sentence is immediately qualified by an explicit enumeration — "(key
  size, nonce size, tag size, key-derivation function and its variant)" — every member of which
  genuinely IS a fixed invariant (§4's table). The falsehood is confined to the word "only" in the
  preceding sentence. E's recommended fix, which would rewrite the enumeration sentence around the
  parameter set, would put the code comment out of step with §4's accounting in the opposite
  direction. Finder DIMENSION I's narrower fix ("drop 'the only'", keep the invariant sentence) is the
  correct one. (2) Finder E cites the spec sentence as docs/format.md:106-108; it actually runs
  106-109 (the "(see §4)" clause is on 109). Finder I's citations (106-109, 371, plan :200-204, :329,
  xml:15) all reproduce exactly. (3) Not a duplicate of PHASE01's F10: that was
  DataDecryptionException's XML doc against §9; this is a different type and a different clause — same
  class of defect, independently reachable. (4) The finders' shared harm scenario is weaker than
  stated: `oaepHash` is a required parameter position on IRsaDataEncryptionService.EncryptAsync and on
  the file extension (shipped xml:298), EncryptionMethod.Rsa's shipped summary (xml:670-671) already
  says "with the padding hash selected at encryption time and recorded in the header (SHA-256, SHA-384
  or SHA-512)", and EncryptedDataHeader.RsaOaepHash (xml:578) documents it too — so a compliance
  caller reaching for the RSA service cannot miss the parameter in IntelliSense. That is why I rate
  this Low rather than the finders' Medium: the consequence is a misleading, self-refuting doc
  sentence, not a design a caller is pushed into. (5) Separately noted but out of scope for this
  claim: docs/guides/ml-kem.md:40 carries the same-shaped "The other degree of freedom is `cipher`"
  phrasing — defensible within the ML-KEM section's scope, but a PHASE04 doc matter.
- *(spec authority lens)* Three corrections to the finders. (1) Finder DIMENSION E is wrong that the
  remark "is false for both of those bytes" and that the fix should list §3.4/§3.5's ML-KEM parameter
  set as another "algorithm selector": §4 counts "exactly **two** algorithmic fields" and deliberately
  does not include the parameter-set byte, so E's recommended rewrite would put the comment into a
  *new* disagreement with §4. (The parameter set is caller-chosen and header-recorded, so the remark's
  second sentence, "Everything else … is not header-selectable", does overreach if "everything else"
  is read as exhaustive rather than as the parenthetical's four fixed items — key size, nonce size,
  tag size, KDF and its variant, all genuinely fixed — but the spec's taxonomy does not license
  calling it algorithmic. Finder DIMENSION I's narrower fix, mirroring §2.4's two-field wording, is
  the correct one.) (2) The severity framing "changes a caller's design" is not established: the OAEP
  hash is announced in bold in IRsaDataEncryptionService's type <remarks>, appears as a named optional
  parameter in EncryptAsync's signature with its own <param> documentation and an
  ArgumentOutOfRangeException row, and is stated in docs/guides/rsa.md:30 — a caller under a
  SHA-384/SHA-512 key-transport policy cannot reach an RSA encrypt call without meeting it. (3) This
  is a code-comment defect, not a spec-conformance defect: RsaOaepHashWire, HeaderWriter and
  HeaderReader all implement §3.3 correctly and are pinned by RsaOaepHashWireTests and
  FormatLayoutTests, so no container bytes and no fixture are implicated, and the fix touches neither
  format version 0x10 nor any committed fixture. Line citations check out: Cipher.cs:8-13,
  Enigma.DataEncryption.xml:13-18 identically in all three built TFM outputs, docs/format.md:106-109
  and 371-372.
- *(reproducibility lens)* (1) Finder DIMENSION E says the .xml is emitted "for all four TFMs" — the
  library multi-targets three (`netstandard2.0;net8.0;net10.0`, csproj line 5); I confirmed exactly
  three copies in the nupkg. (2) Finder E also calls the remark's second sentence ("Everything else …
  is not header-selectable") false because the ML-KEM parameter-set byte is header-selectable. That
  over-reaches: the remark's parenthetical enumerates key size, nonce size, tag size, KDF and its
  variant, all of which §4's table still lists as fixed invariants, and §4:371 says a container
  carries "exactly **two** algorithmic fields", enumerating only the cipher byte and 0x03's OAEP hash
  — the parameter set is a security-level selector the spec does not count here. The single false
  clause is "this is the only algorithmic degree of freedom the format offers"; recommending deletion
  of the "everything else" sentence would introduce a new disagreement with §4. (3) Minor citation
  drift: finder I's acceptance-criterion cite ":329" is the third line of a criterion spanning
  docs/plan/FEATURE-0D64.md:327-329. All other quoted line numbers I checked (Cipher.cs:8-13,
  format.md:106-109 and 371-372, the .xml line 15, HeaderReader.cs:209-210, plan:134-141 and 202-204,
  done:20-22) reproduce exactly, and `grep -rn "algorithmic" --include=*.cs src/` returns Cipher.cs:10
  as the sole in-code instance.

**Refutation record.**
- **correctness — not refuted:** "I read both sides verbatim and could not kill this:
  src/Enigma.DataEncryption/Cipher.cs:9-12 still asserts the cipher byte "is the only algorithmic
  degree of freedom the format offers" and points the reader at "docs/format.md §2.4 and §4", while
  docs/format.md:106-109 says it "is one of only **two** algorithmic degrees of freedom the format
  offers — the other being method `0x03`'s RSA-OAEP hash (§3.3)" and docs/format.md:371-372 says "A
  container carries exactly **two** algorithmic fields" — so the comment contradicts the exact two
  sections it cites, it is compiled into the shipped Enigma.DataEncryption.xml line 15 for all three
  TFMs, and it is not a documented deliberate choice but a genuine miss: FEATURE-0D64's plan made non-
  self-contradiction an acceptance criterion (:329) and enumerated the in-code XML docs to update
  (:134-141), that list is RSA-scoped, `grep -n "Cipher.cs" docs/plan/FEATURE-0D64.md
  docs/done/FEATURE-0D64.md` returns nothing, and `git show --stat 3443bcb` touched no cipher file."
- **spec authority — not refuted:** "I read Cipher.cs, the three built Enigma.DataEncryption.xml
  files, docs/format.md §2.4 and §4, and the FEATURE-0D64 plan/done records myself, and the core
  observation holds — the shipped public remark on the Cipher enum says the cipher byte is "the only
  algorithmic degree of freedom the format offers" and cites §2.4 and §4, the two sections
  FEATURE-0D64 rewrote to say "one of only **two**" and "exactly **two** algorithmic fields" (git log
  confirms Cipher.cs has been untouched since FEATURE-00E7, and the plan's stale-XML-doc checklist at
  :134-141 is RSA-scoped and omits it) — but the consequence is far smaller than the finders claim,
  because the library's wire behaviour conforms exactly, no third-party reader working from
  docs/format.md (the only conformance audience §1.1 and §10 scope) can observe the difference, and
  the finders' compliance-caller harm scenario is defeated by the fact that a caller needing
  SHA-384/SHA-512 must go through IRsaDataEncryptionService, whose type remarks bold-face "The OAEP
  padding hash is selected at encryption time and recorded in the header", whose EncryptAsync
  signature carries a documented `RsaOaepHash oaepHash = RsaOaepHash.Sha256` parameter, and whose
  guide (docs/guides/rsa.md:30) opens "There are exactly **two** algorithm choices to make on the RSA
  side" — so this stands as a one-line stale-comment fix on the most-read enum in the package, at Low,
  not Medium."
- **reproducibility — not refuted:** "I reproduced the disagreement end to end rather than trusting
  the finder: a scratchpad probe against the prebuilt Release DLL encrypted the same plaintext under
  all three accepted OAEP hashes and printed header offset 5 as 0x02/0x03/0x04 with the inspector
  reading back RsaOaepHash=Sha256/Sha384/Sha512, proving the format does offer a second caller-
  selected, header-recorded algorithmic field, while `docs/format.md` §2.4 (lines 106-109) and §4's
  closing paragraph (lines 371-380) both say "two" — yet `src/Enigma.DataEncryption/Cipher.cs:9-10`
  still asserts the cipher byte "is the only algorithmic degree of freedom the format offers" and
  points the reader at those very two sections; I further packed a copy of the library outside the
  repo and unzipped the resulting `Enigma.DataEncryption.1.0.0.nupkg`, finding that false sentence at
  line 15 of `lib/net10.0`, `lib/net8.0` and `lib/netstandard2.0`'s `Enigma.DataEncryption.xml`, so
  this is shipped IntelliSense text and not an internal note — the claim stands, though only at Low
  severity because `IRsaDataEncryptionService`'s own remarks document the selectable hash in bold and
  the `oaepHash` parameter is on the signature, so the finder's "caller never discovers it" harm is
  largely blocked."

**Strongest surviving counter-argument.** This is prose on an enum, not a wire-format or behavioural
defect: no byte changes, no container is mis-decrypted, and nothing a third-party implementer would
read (they read docs/format.md, which is correct and self-consistent). The concrete harm the finders
assert — a compliance-bound caller failing to discover the OAEP-hash option — does not survive
contact with the actual API surface: `IRsaDataEncryptionService`'s type remarks lead with "**The
OAEP padding hash is selected at encryption time and recorded in the header.**", the `oaepHash`
parameter is on every RSA encrypt overload with its own `<param>` doc naming SHA-256/384/512, and
`EncryptedDataHeader` exposes an `RsaOaepHash` property, so anyone reading IntelliSense for RSA
encryption is told immediately. A reader of the `Cipher` enum is asking "which cipher?", and for
that question every word of the remark is true. One could also argue the sentence is scoped by its
own context — it opens "All four ciphers are equivalent 256-bit AEADs" — and that the fix is a one-
word edit with no code consequence, i.e. an Observation rather than a finding. What defeats the
counter-argument only partially is that the remark explicitly cites §2.4 and §4, the two passages
that state the opposite number, and FEATURE-0D64's plan made non-contradiction of exactly this claim
an acceptance criterion; so it is a real, missed, shipped inconsistency — just a cheap one.

---

### F14 — `DataEncryptionDefaults`' shipped public XML says of a group that explicitly includes `FormatVersion` that "they are not stored in the container header" — but §2.3 puts it at offset 3

**Severity:** Low (verifier opinions: Low / Low / Low) · **Candidate:** C06 · survived 3 of 3
**Location:** `src/Enigma.DataEncryption/DataEncryptionDefaults.cs:7-13` and `:25-29`; shipped as `Enigma.DataEncryption.xml:36-43`; contradicts `docs/format.md:59` and §2.3 (`docs/format.md:87-92`); written at `Internal/HeaderWriter.cs:223`, enforced at `Internal/HeaderReader.cs:82-87`

**What is wrong.** The class remark names a compound subject — "The size constants
(`DataKeySizeBytes`, `NonceSizeBytes`, `SaltSizeBytes`, `GcmMacSizeBits`, `KeyConfirmationTagSizeBytes`)
**and `FormatVersion`**" — and then says of that group: "they are **not stored in the container header**
and are not selectable."

For the five size constants that is true and is exactly §4's point. For `FormatVersion` it is flatly
false: §2's table puts the format version at **offset 3**, §2.3 requires a reader to reject anything but
`0x10`, `HeaderWriter` writes it into the common prefix of all five shapes, `HeaderReader` reads and
enforces it, and every committed fixture carries `0x10` at byte 3 (`argon2-aes.bin` → `EC DE 02 10 01`,
`hybrid-aes.bin` → `EC DE 05 10 01`, `mlkem-1024-aes.bin` → `EC DE 04 10 01`). The remark has stretched
§4's "None of them is stored in the header" — true of §4's table, which has no format-version row — over
a field §2 puts on the wire.

The property's *own* summary two lines below is correct ("The format version written to, and required at,
header offset 3"), so the file contradicts itself.

**Failure scenario.** A caller reading the type's IntelliSense to understand what a container carries is
told the format version is not in it. The concrete harm is bounded — the packed XML carries no offset
table from which anyone could parse a container — but this is shipped public documentation asserting the
opposite of the contract about a field that occupies a whole byte of every container ever written.

**Recommended fix.** Change the code doc. Split `FormatVersion` out of the "not stored in the header"
sentence: it is an invariant of the format *and* it is on the wire — those are different properties, and
the remark currently conflates them.

**Corrections applied during refutation.**
- *(correctness lens)* Both finders' citations reproduce exactly as quoted —
  DataEncryptionDefaults.cs:7-13 and 25-29, HeaderWriter.cs:218-225 (the FormatVersion write is line
  223), HeaderReader.cs:82-87, docs/format.md:59 / 87-92 / 345-348, and the XML at lines 36-42 — and
  DIMENSION I's fixture probe (hybrid-aes.bin -> ecde 05 10 01) is correct; I found nothing to correct
  in the mechanism, arithmetic or line numbers. Two things in the framing I do correct as overstated:
  (a) both finders' interop failure scenarios ("their reader accepts a legacy 0x01-0x0F container",
  "they omit the version byte from a hand-written writer, every subsequent offset off by one") are not
  reachable from this text alone — the very next member's own summary, three lines below in the same
  file and the same IntelliSense surface, says "The format version written to, and required at, header
  offset 3 ... are reserved for legacy Enigma.Cryptography.DataEncryption containers and are
  rejected", so the packaged documentation states the truth about offset 3 in the place a hand-
  implementer would actually look; (b) DIMENSION I's "Changing one would be a new format version ...
  is incoherent applied to the format version itself" is rhetorical rather than an error — self-
  reference there is odd, not false. The defect is the single false conjunct "they are not stored in
  the container header" applied to FormatVersion, nothing broader.
- *(spec authority lens)* Three corrections to the finders. (1) The "spec-code-disagreement"
  direction label is WRONG: docs/format.md is correct at line 59 and §2.3, and the executable code is
  correct too — HeaderWriter.WriteCommonPrefix (HeaderWriter.cs:223) writes
  DataEncryptionDefaults.FormatVersion as the fourth byte, and HeaderReader (lines 82-87) reads it
  back and throws DataEncryptionFormatException on anything but 0x10, which is precisely what §2.3's
  "must reject" demands. Nothing in the format, the code or the fixtures disagrees. The disagreement
  is between a non-normative type-level <remarks> and the spec — a doc-hygiene defect, not a
  conformance defect, and it should be reported as such rather than as a spec/code conflict. (2) BOTH
  failure scenarios are not credible and must not be published as written. DIMENSION I's "their reader
  accepts a legacy 0x01–0x0F container" and DIMENSION E's "produce or misparse containers by one byte
  at offset 3, every subsequent offset off by one" both require an implementer building a container
  reader or writer from the packaged .xml alone — which is impossible, because the packed XML contains
  no offset table, no per-method header layout, no combiner labels and no salt/nonce placement. §1.1
  ("a hand-written reader in another language must get this right") and §10 ("a conforming reader ...
  rejects both") scope third-party conformance to readers working from docs/format.md, which never
  misstates the version's presence. The real consequence is confined to one self-contradictory
  sentence in IntelliSense. (3) The finders overstate the extent of the error. Only the clause "they
  are not stored in the container header" is false of FormatVersion; the conjoined "and are not
  selectable" is TRUE of it (that is the actual contrast being drawn with the next paragraph's cost
  constants, which are caller-selectable and written into the header), and "Changing one would be a
  new format version" is tautological for the version constant rather than "incoherent" as DIMENSION I
  asserts. Note also the mitigation the finders acknowledge but discount: the correct statement sits
  four lines below in the same file and the same generated XML — FormatVersion's own member summary
  reads "The format version written to, and required at, header offset 3" — and that member summary,
  not the type remark, is what IntelliSense surfaces when a consumer hovers the constant;
  EncryptedDataHeader.FormatVersion further exposes the field publicly as something read out of a
  header.
- *(reproducibility lens)* (1) Finder DIMENSION I calls the closing sentence "Changing one would be
  a new format version" *incoherent* applied to FormatVersion; it is not incoherent, it is
  tautologically true — the defect is the preceding clause alone, not that one. (2) Both finders'
  failure scenarios overreach: the very next member in the same file (DataEncryptionDefaults.cs:25-29)
  documents FormatVersion as "written to, and required at, header offset 3", and
  EncryptedDataHeader.cs:35-38 documents the property the same way, so the per-member IntelliSense a
  hand-parser author would actually hover states the truth; only the type-level remark is wrong, which
  caps the realistic harm well below "every subsequent offset off by one". (3) I did NOT run `dotnet
  pack` (code freeze), so "shipped in the .nupkg" rests on the SDK default for
  GenerateDocumentationFile=true (csproj:8) plus the observed .xml in
  bin/Release/{netstandard2.0,net8.0,net10.0}/, not on an inspected package. (4) Finder E's incidental
  point that docs/format.md is not packed is correct — the csproj's None ItemGroup packs README.md and
  LICENSE.md only. (5) All cited line numbers check out exactly: docs/format.md:59 (offset-3 row),
  HeaderWriter.cs:223 (the write), HeaderReader.cs:82-87 (read + reject),
  Enigma.DataEncryption.xml:36-43 (the remark, false clause on line 41).

**Refutation record.**
- **correctness — not refuted:** "I read both sides in full myself and the claim stands:
  DataEncryptionDefaults.cs:8-12 (shipped verbatim in bin/Release/net10.0/Enigma.DataEncryption.xml
  lines 36-42, i.e. in the packed IntelliSense surface) says of a group that explicitly includes
  FormatVersion that "they are not stored in the container header and are not selectable", while
  docs/format.md:59 puts the format version at offset 3, §2.3 (docs/format.md:87-92) requires a reader
  to reject anything but 0x10, HeaderWriter.cs:223 writes DataEncryptionDefaults.FormatVersion into
  the common prefix of all five shapes, HeaderReader.cs:82-87 reads and enforces it, and every
  committed fixture I dumped has byte 3 == 0x10 (argon2-aes.bin ecde021001, hybrid-aes.bin ecde051001,
  mlkem-1024-aes.bin ecde041001) — the remark has stretched §4's "None of them is stored in the
  header" (docs/format.md:347-348, whose table indeed has no format-version row) over a field §2 puts
  on the wire, so one of the six named constants is misdescribed in shipped public documentation; it
  is real but confined to a misleading doc sentence, hence Low."
- **spec authority — not refuted:** "I reproduced the offending sentence in
  DataEncryptionDefaults.cs:8-12 and in the shipped Enigma.DataEncryption.xml:38-41, confirmed against
  docs/format.md:59 and §2.3 (docs/format.md:87-92) that the format version is a whole byte of the
  common prefix at offset 3, and confirmed byte 3 == 0x10 in the committed fixtures argon2-aes.bin /
  argon2-twofish.bin / hybrid-aes.bin — so the shipped public statement "they are not stored in the
  container header", applied to FormatVersion, is flatly false and the claim stands, but only as a
  documentation defect: the executable code conforms exactly (HeaderWriter.cs:223 writes 0x10 at
  offset 3, HeaderReader.cs:82-87 rejects every other value, honouring §2.3's "must reject"), the
  normative spec is correct throughout, and both finders' interop failure scenarios are fabricated
  because the packed XML carries no offset table, field layout or KDF constant from which anyone could
  write or parse a container."
- **reproducibility — not refuted:** "I reproduced this from primary sources rather than the
  finders' evidence — the class-level <remarks> in DataEncryptionDefaults.cs:7-13, shipped verbatim in
  the generated Enigma.DataEncryption.xml:36-43 for all three TFMs, names FormatVersion in a compound
  subject and then says of it "they are not stored in the container header", while my own probe
  against the prebuilt Release DLL produced a live container whose byte 3 is 0x10, the shipped
  inspector reported it as EncryptedDataHeader.FormatVersion, editing that byte to 0x01 raised
  "Unsupported container format version 0x01; this library reads 0x10 only.", and all sixteen
  committed container fixtures across all five method shapes carry 0x10 at offset 3 — so the shipped
  public statement is flatly false for one of the six constants it groups, and the claim stands as a
  Low-severity doc defect."

**Strongest surviving counter-argument.** The only wrong text is explanatory prose in a code
comment. It is not in docs/format.md, which the repository declares to be the contract and which is
correct at both the §2 table row (line 59) and §2.3 (lines 87-92); it carries no normative "must";
and the executable behaviour it fails to describe conforms perfectly — every container this library
writes has 0x10 at offset 3, and every container it reads is rejected if that byte differs, so no
reader in any language can observe a difference in a single byte. The document, read whole, already
says the right thing in the very place a consumer would look: the FormatVersion field's own summary,
four lines below the offending sentence and in the same shipped XML, states "written to, and
required at, header offset 3", and that is the tooltip IntelliSense shows for the constant; the
type-level remark is only rendered when hovering the class name, in a paragraph whose evident
purpose is to contrast non-selectable invariants with the caller-overridable cost constants — a
contrast under which the load-bearing half ("not selectable") is true of FormatVersion. The harm
chain therefore has to be invented: no third party can write or parse a container from a .NET XML
doc that contains no offset table, no field layout and no KDF constants, so the "off-by-one at
offset 3" and "accepts a legacy 0x01–0x0F container" scenarios cannot occur. Under this lens's
explicit refutation grounds — the clause is non-normative prose, the document already covers it
elsewhere, and no reader could observe the difference — the claim should be dismissed as a trivial
comment nit that would not justify a branch.

---

### F15 — §2.4 and §4 both state a container carries exactly **two** algorithmic fields; the ML-KEM parameter-set byte is a third, and it is the one whose values *are* a strength ladder

**Severity:** Low (verifier opinions: Low / Low / Low) · **Candidate:** C03 · survived 2 of 3
**Location:** `docs/format.md:106-109` (§2.4), `docs/format.md:371-380` (§4) — contradicted by `docs/format.md:174-175` (§3.3), `docs/format.md:211` (§3.4 offset-5 row) and `docs/format.md:244` (§3.5 offset-5 row)

**What is wrong.** §4 states without qualification: "A container carries exactly **two** algorithmic
fields, and each is admitted on the same narrow ground: within it, no accepted value is a downgrade of
another" — then bullets only the cipher byte and method `0x03`'s OAEP-hash byte. §2.4 says the same in
different words.

But §3.3, eleven lines earlier in the same document, calls the offset-5 field "their algorithm selector"
and says "all **three** public-key methods carry their algorithm selector in the same place".
`FormatLayout`'s own remark says "both methods put a one-byte algorithm selector at offset 5". The
parameter-set byte at offset 5 of methods `0x04` and `0x05` is a header-carried, one-byte selector naming
one of three algorithms — structurally identical to the OAEP-hash byte the same document does count.

The sharper half: §4 admits a header algorithm field on one stated ground — that within it no accepted
value is a downgrade of another. ML-KEM-512, -768 and -1024 are NIST security categories 1, 3 and 5. That
ground **demonstrably does not hold** for the omitted third field, which is presumably why counting it
would have been awkward.

**Failure scenario.** A reviewer or implementer auditing the format's attack surface reads §4, takes the
"exactly two" inventory at face value, and never asks what protects the third selector. The answer is
reassuring — the spec-authority verifier established by probe that the parameter set is
credential-determined rather than sender-selectable (declaring a set other than the recipient key's own
throws `ArgumentException` at encrypt time) and that an edited byte fails before a payload byte is read —
but that answer appears nowhere in the document, precisely because the document does not admit the field
exists in this class.

**Recommended fix.** Change the spec. Either count the parameter-set byte and give it its own admission
ground — it is determined by the recipient's key rather than offered to a sender, so it is not a
negotiation lever even though its values are a ladder — or say explicitly that §4 is counting
*sender-selectable* algorithmic fields and that the parameter set is credential-determined. The second is
smaller and is what the spec-authority verifier judged the document already means.

**Corrections applied during refutation.**
- *(correctness lens)* (1) DIMENSION E's key evidence command `sed -n 345,400p docs/format.md | grep
  -n -i "parameter set|ml-kem|0x04"` is a broken regex — without `-E`, `|` is a literal, so the empty
  output was guaranteed regardless of content and proved nothing. I re-ran it as `grep -nEi` over
  lines 345-400 and over the whole file: §4 genuinely never mentions the ML-KEM parameter set, so the
  conclusion holds but the finder's evidence for it did not. (2) DIMENSION E cites the "all three
  public-key methods carry their algorithm selector in the same place" sentence at
  docs/format.md:190-191; it is at lines 174-175 (DIMENSION C cited it correctly). (3) DIMENSION C
  cites the §4 sentence as spanning 371-374; the sentence is 371-372, the bullets start at 374. (4)
  Both finders frame this as a FEATURE-0D64-era count error. It is older: `git show
  a3e8329:docs/format.md` shows FEATURE-00E7 wrote "The only algorithmic field a container carries is
  the cipher byte" in the very commit that introduced §3.4's line-180 "Parameter set — 0x01 ML-KEM-512
  · 0x02 ML-KEM-768 · 0x03 ML-KEM-1024" row, so the enumeration was already wrong before the hash byte
  existed and FEATURE-0D64 mechanically bumped "only" to "two" without revisiting the class. (5)
  Neither finder notes the strongest mitigating fact I found: the parameter set is NOT freely
  selectable per container — IMLKemDataEncryptionService/IHybridDataEncryptionService document and
  enforce that the public key "must match parameterSet", throwing ArgumentException otherwise, so the
  sender is bound by the recipient's key pair and an attacker editing offset 5 gets a decapsulation
  failure (§9:584), never a silent downgrade. The security posture is fine; the defect is confined to
  the document's own enumeration and rationale.
- *(spec authority lens)* Four. (1) Finder DIMENSION E quotes §4's "None of them is stored in the
  header, and none is selectable" as the section's framing for header-carried algorithm choices; it is
  scoped to the fixed-parameter table it immediately introduces, and §4.1 says the opposite of header-
  carried fields by design ("These are defaults chosen at encryption time — they *are* stored in the
  header"), so it cannot bear the exhaustive-enumeration reading the failure scenario needs. (2)
  Finder E cites the "all three public-key methods carry their algorithm selector in the same place"
  sentence at docs/format.md:190-191; it is at 174-175 (finder C cited it correctly). (3) Finder C's
  "there is no paragraph anywhere arguing why an attacker-editable parameter-set byte is not a
  downgrade lever" is overstated: §5 states "Any edit to any header byte is an authentication
  failure", §4 explicitly cross-references it ("The header *is* authenticated — §5 — so an edit would
  be detected"), and §9's ML-KEM note names an edited parameter-set byte as a case it deliberately
  maps to DataDecryptionException; my probe reproduces exactly that. (4) Finder E's claim that
  docs/guides/ml-kem.md:39-41 "already contradicts §4" inverts the guide: lines 30-34 of that same
  guide state a parameter set not matching the key pair throws ArgumentException, i.e. the guide
  documents the very credential-binding that puts the field outside §4's class, and its "choice" is
  about EncryptAsync's argument list, not about header-carried algorithmic fields. Finder E's
  container figures are accurate (byte@5 = 0x01/0x02/0x03, header lengths 806/1126/1606, hybrid 1066)
  and I reproduced them.
- *(reproducibility lens)* (1) Both finders imply the parameter-set byte is a sender-side degree of
  freedom comparable to the cipher byte; my probe section C shows it is NOT freely selectable —
  encrypting with an ML-KEM-512 public key while declaring MLKem1024 is rejected before any byte is
  written: "System.ArgumentException: The ML-KEM public key could not be used to encapsulate a shared
  secret. It is malformed, or it is not a MLKem1024 key. (Parameter 'publicKey')" with an inner
  CryptographicException. The sender picks the parameter set by picking the key pair. (2) Finder
  DIMENSION C writes that the byte is "attacker-editable" and that "there is no paragraph anywhere in
  the normative document arguing why an attacker-editable parameter-set byte is not a downgrade
  lever". Editing it achieves no downgrade — probe section D edits a genuine ML-KEM-1024 container's
  byte to 0x01 and decryption fails with Enigma.DataEncryption.DataDecryptionException ("...it may not
  be a MLKem512 key — which is what the container's parameter-set byte claims it was encapsulated
  under") — and §4 does carry a document-wide answer to editability: "(The header *is* authenticated —
  §5 — so an edit would be detected...)" at docs/format.md:367-369. The real gap is the count and the
  admission ground, not an unargued attack. (3) Citation errors: finder DIMENSION E cites the §3.3
  "algorithm selector" sentence at docs/format.md:190-191; it is at 174-175 (DIMENSION C cites it
  correctly). The §3.4 parameter-set table row is at line 211, not 210. (4) Neither finder noticed the
  closely related shipped-XML-doc defect I found while verifying:
  src/Enigma.DataEncryption/Cipher.cs:9-12 still says of the cipher "this is the only algorithmic
  degree of freedom the format offers ... See docs/format.md §2.4 and §4" — the pre-FEATURE-0D64
  wording, now contradicting even the current §2.4's "two", in a doc comment that ships in the
  package's XML documentation file.

**Refutation record.**
- **correctness — not refuted:** "I read §2.4, §3.3, §3.4, §3.5 and §4 of docs/format.md in full,
  re-ran the finder's grep correctly (their `grep -n -i "parameter set|ml-kem|0x04"` lacked `-E`, so
  it was a literal-pipe pattern that could never match and proved nothing), and independently
  confirmed both halves: §4 lines 371-372 state without qualification "A container carries exactly
  **two** algorithmic fields, and each is admitted on the same narrow ground: within it, no accepted
  value is a downgrade of another" and bullet only the cipher and method 0x03's OAEP-hash byte, while
  §3.3 line 174-175 of the same document says "all three public-key methods carry their algorithm
  selector in the same place" and FormatLayout.cs's own remark says "both methods put a one-byte
  algorithm selector at offset 5" — and my own probe against the prebuilt Release assembly produced
  method-0x04 containers with byte@5 = 0x01/0x02/0x03 for ML-KEM-512/768/1024 (headerLen
  806/1126/1606), each surfaced by the shipped inspector as `MLKemParameterSet`; the reading that
  would save §4 (that the parameter set is credential-determined rather than a negotiation lever) is
  nowhere written, and §4's *stated* admission ground is strength-equivalence, which is plainly false
  for a 512/768/1024 ladder spanning NIST categories 1/3/5, so §4's downgrade analysis has a genuine
  hole rather than merely a miscount — the claim stands as a spec-internal inconsistency with no code
  defect, and it long predates FEATURE-0D64 (commit a3e8329 wrote "the only algorithmic field a
  container carries is the cipher byte" in the same commit that introduced §3.4's parameter-set row)."
- **spec authority — **refuted**:** "I re-read §2.4/§3.3/§3.4/§3.5/§4/§4.1/§5/§8/§9 whole and probed
  the shipped Release assembly, and the ML-KEM parameter-set byte does not belong to the class §4 is
  counting: §4's admission criterion is about choices the format offers a sender ("There is no
  'negotiation' to be had, so the format offers none"), and my probe shows the parameter set is not
  offered at all — declaring any set other than the recipient key's own throws ArgumentException at
  encrypt time ("it is not a MLKem512 key. (Parameter 'publicKey')") while an edited byte@5 yields
  DataDecryptionException before a payload byte — exactly like the header-carried RSA modulus size N,
  a genuine 1024/2048/4096 strength ladder visible at offset 18 and capped in §8 that §4 has likewise
  never counted because it is a property of the credential rather than a selector; the normative
  reading path an implementer must follow (§3.4/§3.5's offset-5 table rows with their wire mapping,
  §7.2 step 2, §9's undefined-byte row) fully specifies the field, so no reader can emit or accept a
  wrong byte, and all that survives is one loose word in non-normative rationale prose — §3.3's layout
  remark calling it "their algorithm selector"."
- **reproducibility — not refuted:** "I reproduced the claim end-to-end with a standalone probe
  against the prebuilt Release DLL — real 0x04 containers carry 0x01/0x02/0x03 at offset 5 (header
  806/1126/1606) and real 0x05 containers carry the same byte (header 1066 for ML-KEM-512, 1866 for
  ML-KEM-1024), all honoured by the reader and surfaced by the inspector — and confirmed by quoting
  the document against itself that docs/format.md:174-175 (§3.3) calls that byte the "algorithm
  selector" carried by "all three public-key methods" while docs/format.md:106-109 (§2.4) and
  docs/format.md:371-372 (§4) both state in bold that the format offers exactly **two** algorithmic
  fields and enumerate only the cipher byte and method 0x03's OAEP hash, so the spec contradicts
  itself and — because ML-KEM-512/768/1024 are NIST categories 1/3/5, a genuine strength ladder — the
  sole ground §4 offers for admitting a header algorithm field ("within it, no accepted value is a
  downgrade of another") demonstrably does not hold for the omitted third field; the claim stands,
  though only as a prose defect, since my probe also shows the field is credential-determined
  (declaring MLKem1024 with an ML-KEM-512 key is rejected with ArgumentException) and an edited
  offset-5 byte yields a DataDecryptionException rather than any silent downgrade."

**Strongest surviving counter-argument.** §4 is titled "Fixed parameters" and its subject is
negotiation levers, not an inventory of header fields. Read that way, the parameter-set byte is
descriptive rather than algorithmic-in-§4's-sense: my own probe shows the sender cannot choose it
independently of the credential (an ML-KEM-512 key with parameterSet=MLKem1024 is rejected
outright), so it records a property of the recipient's key exactly as the wrapped-key length N at
offset 18 records the RSA modulus size — and nobody calls N an algorithmic degree of freedom. Nor is
it a downgrade lever: editing offset 5 makes decapsulation fail, so §4's actual conclusion — that
the container offers an attacker nothing to negotiate down to — survives untouched once the field is
considered. The wording has moreover read this way since FEATURE-00E7 ("The only algorithmic field a
container carries is the cipher byte", git a3e8329:docs/format.md:231), authored in the same commit
as §3.4's parameter-set row, which is at least consistent with a deliberate taxonomy rather than an
oversight; §3.4 and §3.5 each give the field its own normative table row, so no implementer building
method 0x04 can miss it and none would emit or accept wrong bytes; and the fix both finders propose
is pure prose in a repo-only document. On that reading the claim is a vocabulary quibble that
changes no byte and no behaviour. What defeats it: the *same document* at §3.3 calls this exact byte
"their algorithm selector" carried by "all three public-key methods", so the spec's own vocabulary
places it in the class §4 says has exactly two members; the three values are three distinct FIPS 203
algorithms at NIST categories 1, 3 and 5, which is precisely the ladder §4's stated admission ground
("no accepted value is a downgrade of another") asserts no header algorithm field contains; and
FEATURE-0D64's acceptance criterion 1 (docs/plan/FEATURE-0D64.md:329) made "the spec does not
contradict itself" an explicit project standard for exactly these two sentences.

---

### F16 — `docs/format.md` never states the character encoding of the password, the one KDF input the contract leaves undefined

**Severity:** Low (verifier opinions: Low / Low / Low) · **Candidate:** C12 · survived 3 of 3
**Location:** `docs/format.md:128` (§3.1), `docs/format.md:145-146` (§3.2), `docs/format.md:348-361` (§4's table); `src/Enigma.DataEncryption/Internal/PasswordCredential.cs:56`

**What is wrong.** §3.1 gives the data key as `PBKDF2-HMAC-SHA256(password, salt, iterations, 32)` and
§3.2 as `Argon2id(password, salt, …, 32)`, with `password` an undefined symbol. `docs/format.md` contains
no occurrence of "UTF-8", "UTF8" or any normalization rule, and §4's table of fixed invariants omits the
encoding. The library hard-codes `Encoding.UTF8.GetBytes` at `PasswordCredential.cs:56`, reached from all
`char[]` service paths.

What keeps this from being purely out of scope is §2.2's own credential column, which **does** pin the
byte form of the other two credentials — "RSA key pair (PEM)", "ML-KEM key pair (raw FIPS 203 bytes)" —
and gives only the bare word "password" for `0x01`/`0x02`. Credential representation is demonstrably
inside this document's scope; the password's is the one instance left unstated.

**Failure scenario.** Verified by probe: a container written with the `char[]` password `"pässwörd"`
opens only under its UTF-8 octets — UTF-16LE, UTF-16BE and Latin-1 each fail with the
key-confirmation error — and an NFD password does not open an NFC container. A third-party implementer
writing a reader in a language whose default string encoding is UTF-16 produces a byte-perfect container
that no `char[]` caller of this library can open, and the error says only "the password is wrong".

**Recommended fix.** Change the spec. Add one row to §4 or one sentence to §3.1/§3.2: where a credential
is supplied as text, it is encoded **UTF-8 with no normalization and no trailing NUL**; the primary
`byte[]` overload leaves the encoding to the caller. Note the correction below — do **not** phrase it as
a "not selectable" invariant, because the `byte[]` overload makes it caller-selectable by design.

**Corrections applied during refutation.**
- *(correctness lens)* Three corrections to the finder. (1) Wrong line number: the Encode expression
  is at PasswordCredential.cs:56, not :57 (line 57 is the closing brace). (2) Materially wrong claim
  about where the encoding is documented: the finder says it appears "only in docs/guides/password-
  based.md:188 and file-operations.md:373 ... which are repo-only and never packed." It is also stated
  on the public API surface — IPbkdf2DataEncryptionService.cs:75,157 and
  IArgon2DataEncryptionService.cs:90,183 ("They are UTF-8-encoded into a temporary buffer") — and
  GenerateDocumentationFile is true (src/Enigma.DataEncryption/Enigma.DataEncryption.csproj:8), so the
  built Enigma.DataEncryption.xml carries "UTF-8-encoded into a temporary buffer" on every char[]
  password param and ships with the package. Every .NET consumer sees it in IntelliSense, which
  largely dissolves the finder's secondary ".NET caller reaches for the byte[] overload" scenario; the
  surviving harm is the hand-written-reader interop case alone. (3) "It is the only KDF input in
  sections 3.1/3.2 whose byte representation the contract never defines" is an overstatement: §3.2's
  Argon2id parameter list also omits Argon2's optional secret key K and associated data X, which a
  conforming implementer must likewise assume empty. Also noted but not cited by the finder:
  PasswordCredential.cs:17-21 does carry a deliberate-choice argument for the fixed encoding ("A
  password is only ever compared against itself through the derived key ... the container carries no
  encoding field to disagree about"), which defends non-configurability and the absence of a header
  field but says nothing about a second implementation, so it does not defeat the interop point.
- *(spec authority lens)* Five corrections. (1) The finder's premise that §4 is "the exhaustive list
  of format invariants that are not stored in the header" is his own inference — §4 says "These are
  invariants of the format. None of them is stored in the header, and none is selectable", which is a
  property of the listed rows, not a completeness claim; the only exhaustiveness the section asserts
  is "a container carries exactly two algorithmic fields", which is about header fields. (2) The
  finder is wrong that UTF-8 "is documented only in docs/guides/password-based.md:188 and file-
  operations.md:373, which CLAUDE.md classes as usage": UTF-8 is stated on the XML `<param>` doc of
  every public char[] entry point — IPbkdf2DataEncryptionService.cs:75 and :157,
  IArgon2DataEncryptionService.cs:90 and :183, and DataEncryptionFileExtensions.cs:47, 105, 175, 256,
  331 — and therefore ships in the generated Enigma.DataEncryption.xml, i.e. in IntelliSense for every
  .NET consumer. My earlier grep appeared to confirm the finder only because `head -40` truncated the
  alphabetically later file. (3) The failure scenario's alternative encodings are mis-chosen: it says
  an implementer would "pick UTF-16LE (the natural .NET/Java string encoding)", but Java's
  `String.getBytes()` never yields UTF-16LE and Python's `str.encode()` defaults to UTF-8, so the two
  languages the scenario names would most probably land on the library's actual choice. (4) The
  byte[]-overload sub-scenario is licensed behaviour, not a contract gap:
  IPbkdf2DataEncryptionService.cs:36/116 documents the bytes as "used as supplied... the caller owns
  both its encoding and its lifetime", and PasswordCredential's own remarks record that "the container
  carries no encoding field to disagree about" — an intentional design, not an omission. (5) The
  claim's supporting citation set is incomplete in its own favour: §2.2 (docs/format.md:72-78), not
  §4, is the clause that makes this a genuine internal inconsistency.
- *(reproducibility lens)* Three corrections to the finder. (1) The finder states the UTF-8 choice
  "is documented only in docs/guides/password-based.md:188 and file-operations.md:373, which CLAUDE.md
  classes as usage, not the contract, and which are repo-only and never packed." That is wrong: it is
  documented in the SHIPPED public XML documentation (GenerateDocumentationFile=true in
  src/Enigma.DataEncryption/Enigma.DataEncryption.csproj:8) at ten sites —
  IPbkdf2DataEncryptionService.cs:75 and :157, IArgon2DataEncryptionService.cs:90 and :183,
  DataEncryptionFileExtensions.cs:47, :105, :175, :256, :331 — each reading "The password characters.
  They are UTF-8-encoded into a temporary buffer which is cleared before returning". Every .NET caller
  who can reach a char[] overload is told at the call site. (2) The finder asserts "Section 4 is the
  exhaustive list of format invariants that are not stored in the header." docs/format.md never claims
  exhaustiveness; §4 says only "These are invariants of the format. **None of them is stored in the
  header, and none is selectable.**" — a statement about the listed rows. The exhaustiveness premise
  is the finder's, not the document's, and it is what makes the finder's proposed §4 row look
  mandatory. (3) The finder's proposed remedy — adding a §4 row "Password encoding (character inputs)
  | UTF-8, no normalization, no terminator" — would state a falsehood in a section whose lead sentence
  is "none is selectable": my probe confirms the byte[] overloads accept ANY encoding, and
  docs/guides/password-based.md:191 explicitly offers them "when you need an encoding other than
  UTF-8". The correct remedy is a clarifying sentence in §3.1/§3.2 (and/or §2.2's credential table,
  which already gives "PEM" and "raw FIPS 203 bytes" for the other two credentials but bare "password"
  for these two), not a §4 invariant row. Separately, I chased and then killed one of my own side-
  tracks: my probe found that appending trailing NUL bytes to a byte[] password still decrypts
  (b"abc\0" opens a container written under b"abc"), which looked like a defect until my Python cross-
  check reproduced it exactly — it is HMAC's standard zero-padding of sub-block-size keys, identical
  in hashlib, and therefore not a library or spec defect at all.

**Refutation record.**
- **correctness — not refuted:** "I confirmed from primary sources that docs/format.md contains no
  occurrence of "UTF-8"/"UTF8" and that §3.1/§3.2 give only `PBKDF2-HMAC-SHA256(password, salt,
  iterations, 32)` / `Argon2id(password, salt, …, 32)` with no octet-level definition of `password`,
  while §4's self-declared exhaustive table of format invariants that are "not stored in the header,
  and none is selectable" omits the encoding the library hard-codes at
  src/Enigma.DataEncryption/Internal/PasswordCredential.cs:56 (`Encoding.UTF8.GetBytes(password)`,
  reached from all four char[] service paths); acting as the third-party implementer the claim posits,
  I encrypted "pässwördé" through the char[] overload, then reimplemented §3.1 plus §6 in Python from
  the spec text alone and recovered the container's kcTag `f7971a89db77839dca267c608dacb093` only
  under UTF-8 (UTF-16LE and Latin-1 gave different tags, and the byte[] decrypt overload
  correspondingly threw DataDecryptionException for both), so the pinning gap is real and the claim
  stands — but only at Low, because the failure is loud rather than silent, bites non-ASCII passwords
  alone, and the encoding is in fact stated on the packed public XML documentation, not merely in the
  repo-only guides as the finder asserted."
- **spec authority — not refuted:** "I re-grepped docs/format.md end to end and confirmed the
  strings "UTF", "encoding of the password" and any normalization rule are absent — §3.1:128 and
  §3.2:145-146 write `password` as an undefined symbol, §4's fixed-parameter table (lines 348-361)
  omits it, and §10 adds nothing — while `PasswordCredential.Encode`
  (Internal/PasswordCredential.cs:56) hard-fixes `Encoding.UTF8.GetBytes` for all four char[] entry
  points; the claim survives chiefly on a clause the finder never cited, §2.2's credential column
  (lines 72-78), which does pin the byte form of the other credentials ("RSA key pair (PEM)", "ML-KEM
  key pair (raw FIPS 203 bytes)") and gives only the bare word "password" for `0x01`/`0x02`, so
  credential representation is demonstrably in this document's scope and the password's is the one
  instance left unstated — but I rate it Low, not Medium, because every realistic implementer lands on
  UTF-8 anyway (Python's `str.encode()` defaults to it; Java's `String.getBytes()` never yields
  UTF-16LE), the mismatch fails loudly at key confirmation rather than silently mis-decrypting, and
  the encoding is already stated on every public `char[]` parameter's shipped XML documentation."
- **reproducibility — not refuted:** "I re-ran the grep (docs/format.md contains no occurrence of
  "utf-8", "utf8" or "normaliz") and built my own probe against the prebuilt Release DLL, which
  reproduced every behavioural claim — a container written with the char[] password "pässwörd" opens
  only with its UTF-8 octets while UTF-16LE, UTF-16BE and Latin-1 each fail with
  `DataDecryptionException: The password is wrong: the container's key-confirmation tag does not match
  the derived key. No payload byte was read.`, an NFD password does not open an NFC container, and the
  char arrays {'x',U+D800} and {'x',U+DFFF} both encode to `78 EF BF BD` and open each other's
  containers — so the gap is real and the claim stands, but only at Low, because I also re-implemented
  §3.1 in Python from the spec text alone and matched a real container's kcTag byte-for-byte, proving
  a third-party implementer coding against docs/format.md produces and accepts every container byte
  correctly (the undefined thing is the char→octet mapping, which is not a container byte and is in
  fact caller-selectable through the byte[] overload, so the finder's proposed §4 "not selectable" row
  would be false), and the shipped public XML documentation on all ten char[] entry points already
  states "UTF-8-encoded into a temporary buffer", not — as the finder claims — only the repo-only
  usage guides."

**Strongest surviving counter-argument.** The password's character-to-octet mapping is not a
property of the binary container format, so its absence from docs/format.md is scope, not a gap.
§3.1's `password` is an octet string exactly as RFC 8018 §5.2 defines PBKDF2's input, and the
document's own opening sentence says the container carries everything a reader needs "short of the
credential" — the credential is definitionally outside it. I proved the format-level specification
is complete by writing an independent Python reader from the spec text alone: it recomputed K =
PBKDF2-HMAC-SHA256(password_octets, salt, iters, 32), kcKey = HMAC(K, ASCII label), kcTag =
HMAC(kcKey, header[0:37])[0:16] and matched the real container's tag byte-for-byte on the first try.
A third-party implementer therefore produces and accepts every container byte correctly from
docs/format.md; the only thing they must decide is how their application turns a user-typed string
into octets, and that is a decision the .NET side ALSO leaves to the application — the byte[]
overload is first-class and the guides explicitly recommend it "when you need an encoding other than
UTF-8". So UTF-8 is not an invariant of the format at all; it is the convention of one convenience
overload, which is precisely where it is documented (ten shipped XML doc sites plus two guides).
Writing it into §4, whose lead sentence is "none is selectable", would make the contract say
something false. Finally, PasswordCredential.cs:18-21 makes the argument explicitly — "A password is
only ever compared against itself through the derived key, so the one thing that matters is that
both directions encode identically — and the container carries no encoding field to disagree about"
— and the failure mode when it is violated is loud and immediate (key-confirmation mismatch before
any payload byte is read), never silent mis-decryption.

---

### F17 — §2.4's cipher-byte-to-algorithm mapping is unpinned for Serpent (`0x03`) and Camellia (`0x04`): swapping the two factory calls leaves all 28,272 tests green

**Severity:** Low (verifier opinions: Low / Low / Low) · **Candidate:** C10 · survived 3 of 3
**Location:** `src/Enigma.DataEncryption/Internal/CipherResolver.cs:61-64`; `tests/…/Internal/CipherResolverTests.cs:39-51` and `:79-85`; `tests/…/Services/GoldenVectorInventoryTests.cs`; `docs/format.md:99-104`

**What is wrong.** §2.4 is normative about *which algorithm* each cipher byte names — its third column
gives the Enigma.Core factory method per byte — not merely that the four bytes are distinct. Nothing in
the suite asserts that identity for two of the four. `CipherResolverTests` pins byte→enum only, and its
`Resolve_MapsTheFourCiphersToFourDistinctAlgorithms` pins that the four resolve to four *pairwise
different* services, which a permutation satisfies. The only other thing that could freeze the mapping is
a committed container, and every one of the container fixtures is `*-aes.bin` or `*-twofish.bin`.

Serpent and Camellia therefore have no golden container, no independent implementation to compare
against, and no name-level assertion. A permutation of exactly those two is a free move.

**Failure scenario.** Reproduced independently by two verifiers on scratchpad copies of `HEAD`: swapping
the Serpent and Camellia arms of `CipherResolver.Resolve` **builds with zero warnings and leaves all
28,272 tests green**, while the control swap of Twofish and Serpent fails 24 tests (12 per TFM). A future
edit that permutes them ships containers whose byte `0x03` claims Serpent and carries Camellia — a silent
interop break against §2.4 that no gate in this repository would catch.

The shipped mapping is **correct today**: a verifier proved with an independent BouncyCastle probe that
byte `0x03`'s payload matches `SerpentEngine` + GCM byte-for-byte and `0x04`'s matches `CamelliaEngine` +
GCM. This is a pinning gap, not a live defect, which is why all three verifiers put it at Low.

**Recommended fix.** Add the name-level assertion the plan's deliberate-choice 9 does not preclude.
Choice 9 rules out a `*-serpent.bin` golden *container* — this library's own output would prove nothing
about Serpent — but it does not rule out asserting, with an injected recording
`IBlockCipherServiceFactory`, that `Cipher.Serpent256Gcm` calls `CreateSerpentService` and
`Cipher.Camellia256Gcm` calls `CreateCamelliaService`. That is a four-line test that kills the mutation.
This straddles PHASE03's dimension; flagged for PHASE05 to re-home.

**Corrections applied during refutation.**
- *(correctness lens)* (1) The finder says "every one of the eleven container fixtures is *-aes.bin
  or *-twofish.bin". There are THIRTEEN container fixtures, not eleven (16 .bin files minus the 3
  shared-secret files: pbkdf2-aes, pbkdf2-twofish, argon2-aes, argon2-twofish, rsa-aes, rsa-twofish,
  rsa-aes-sha384, rsa-aes-sha512, mlkem-512-aes, mlkem-1024-aes, mlkem-1024-twofish, hybrid-aes,
  hybrid-twofish). The finder's own enumeration lists all thirteen and then miscounts them. The
  substance is unaffected: all thirteen are AES or Twofish. (2) The finder writes that Serpent and
  Camellia have "no independent implementation to compare against" as if Twofish had one. It does not
  — GoldenVectorInventoryTests.cs:53 and Pbkdf2GoldenVectorTests.cs:26-29 declare the Twofish payload
  a self-derived regression vector. What freezes the Twofish mapping is simply that the bytes are
  committed, not that an external oracle produced them. This correction strengthens the claim rather
  than weakening it, and it defuses the obvious defence: a self-derived Serpent fixture would pin the
  mapping just as well. (3) docs/plan/FEATURE-F612.md:99's priming bullet reads "The
  Twofish/Serpent/Camellia payloads of the golden containers are regression vectors by design" — but
  there are no Serpent or Camellia golden containers at all, so that deliberate-choice item
  (provenance #9) is about the provenance of vectors that exist, not about the absence of a pin, and
  does not cover this claim. (4) The finder's severity of Medium is wrong under the audit's own
  rubric: Medium requires that an implementer coding against the spec would produce or accept wrong
  bytes today, and the finder concedes the shipped code is correct. I rate it Low.
- *(spec authority lens)* (1) The audit lead's deliberate-choice #9 as stated to me —
  "Twofish/Serpent/Camellia payloads are declared regression vectors" — is inaccurate for this repo
  and does NOT shield the code here: there are no Serpent or Camellia payload vectors at all. Only
  Twofish payloads are declared regression vectors (Pbkdf2GoldenVectorTests.cs:26-30 and five
  GoldenVectorInventoryTests rows say so); every one of the eleven container fixtures is *-aes.bin or
  *-twofish.bin, which I verified against the inventory list, not just the directory listing. Had #9
  been accurate the claim would have been refuted as contradicting a documented choice. (2) The finder
  is imprecise about what is pinnable: docs/format.md §2.4's third column names the Enigma.Core
  factory method, and no independent Serpent-256-GCM or Camellia-256-GCM implementation is available
  here (the same reason the Twofish vector is only a regression vector), so BOTH of the finder's
  proposed fixes — the four Assert-style factory-identity comparisons and the optional
  *-serpent.bin/*-camellia.bin fixtures — are regression-grade against the factory column, not
  independent verification that CreateSerpentService really implements Serpent. The finder calls the
  fixture option "the stronger fix"; it is stronger only as a wire-level freeze, not as algorithm
  verification. (3) The finder's severity of Medium is wrong under this audit's ladder: Medium
  requires that an implementer working from docs/format.md would today produce or accept wrong bytes,
  and they would not — CipherResolver.cs:63-64 matches docs/format.md:103-104 literally. (4) Line
  citations all check out: CipherResolver.cs:61-64, docs/format.md:99-104 (§2.4 heading at 94, the two
  disputed rows at 103-104), CipherResolverTests.cs:39-51 and 79-85.
- *(reproducibility lens)* Three corrections. (1) The audit lead's deliberate-choice item #9 is
  phrased as "Twofish/Serpent/Camellia payloads are declared regression vectors"; the suite says no
  such thing — Pbkdf2GoldenVectorTests.cs:26-29, Argon2GoldenVectorTests.cs:34-35,
  RsaGoldenVectorTests.cs:160-161, MLKemGoldenVectorTests.cs:176-177 and
  HybridGoldenVectorTests.cs:223-224 declare only the *Twofish* payload a regression vector, and
  Serpent and Camellia have no committed payload vector of any kind, so #9 does not cover this claim.
  (2) The suite's stated rationale for regression-only vectors — "No implementation of Twofish-256-GCM
  is available outside BouncyCastle here" — does not extend to Serpent/Camellia as a defence:
  BouncyCastle is already on the transitive dependency graph and my probe reproduced both
  Serpent-256-GCM and Camellia-256-GCM payloads byte-for-byte, so a genuinely independent vector is
  achievable with no new dependency, and the finder's cheaper name-level fix needs no external
  implementation at all. (3) The finder's severity of Medium is wrong under this audit's rubric:
  Medium requires that a third-party implementer coding from docs/format.md "would produce or accept
  wrong bytes", and my probe shows they would produce exactly the right bytes — the mapping is correct
  today, so Low is the right tier. Minor citation notes, neither material: Inventory() actually spans
  GoldenVectorInventoryTests.cs:40-142 (finder said 38-146), and the FromHeaderByte theory is at
  CipherResolverTests.cs:78-86 (finder said 79-85).

**Refutation record.**
- **correctness — not refuted:** "I read docs/format.md:99-104 (which is normative about the factory
  method each cipher byte names, not merely that the four bytes are distinct), read
  CipherResolver.cs:61-64 and the whole of CipherResolverTests.cs, grepped every Serpent/Camellia
  reference in the suite and the full fixture inventory, and then independently re-ran the finder's
  mutation on a scratchpad copy of HEAD: swapping the Serpent and Camellia factory calls builds with 0
  warnings and leaves all 28,272 tests green, while the control swap of Twofish and Serpent on the
  same copy fails 24 tests — so the claim stands as stated, the mapping §2.4 makes normative is pinned
  by name for AES and by committed fixture for Twofish but by nothing at all for Serpent (0x03) and
  Camellia (0x04)."
- **spec authority — not refuted:** "I reproduced both mutation experiments myself on scratchpad
  copies of HEAD — swapping the Serpent and Camellia arms of CipherResolver.Resolve builds warning-
  free and leaves the suite at 28,272/28,272 green, while the control swap of Twofish and Serpent
  fails 24 tests (12 per TFM) — and I confirmed by reading the fixture inventory
  (GoldenVectorInventoryTests.Inventory) and grepping every Serpent/Camellia occurrence in tests/ that
  nothing anywhere binds Cipher.Serpent256Gcm to CreateSerpentService or Cipher.Camellia256Gcm to
  CreateCamelliaService, so docs/format.md:103-104's normative byte-to-algorithm rows are pinned only
  by reading the source for two of the four ciphers; the claim stands as a genuine, specific pinning
  gap, but it is Low rather than Medium because the shipped code is correct, no container this library
  writes is mislabelled today, and the harm is reachable only through a future erroneous edit."
- **reproducibility — not refuted:** "I reproduced the mutation experiment from scratch on a `git
  archive HEAD` copy in the scratchpad and got exactly the finder's numbers — swapping only the
  Serpent and Camellia arms of `CipherResolver.Resolve` builds with 0 warnings and yields `total:
  28272 / failed: 0`, while the control swap of Twofish and Serpent yields `failed: 24 / succeeded:
  28248` — and I separately proved with an independent BouncyCastle probe against real containers that
  the shipped mapping is in fact correct (the 0x03 payload matches SerpentEngine+GCM byte-for-byte,
  0x04 matches CamelliaEngine+GCM), so the claim stands as a genuine pinning gap against §2.4's
  normative algorithm identity rather than a live defect, and I rate it Low rather than the finder's
  Medium because no byte this library ships today is wrong and the consequence is reachable only
  through a future code edit."

**Strongest surviving counter-argument.** PHASE02 audits conformance between docs/format.md and the
code, and here the code conforms exactly: the two disputed switch arms read `Cipher.Serpent256Gcm =>
factory.CreateSerpentService()` and `Cipher.Camellia256Gcm => factory.CreateCamelliaService()`,
which is a character-for-character restatement of §2.4's own third column, verifiable by eye in less
time than the test would take to write. There is no divergence, present or observable — no container
that exists is mislabelled, no hand-written reader in another language is misled, and §10's
conformance scope (readers) is untouched. The proposed assertion is tautological: it compares a one-
line literal mapping against the very identity it is written from, so it cannot catch a
misunderstanding of the spec, only a mutation, and the mutation it catches (silently permuting two
arms whose method names differ by six letters and survive code review) is not a failure mode anyone
has ever produced. By that standard every literal in the codebase is "unpinned", and the honest
verdict is mutation-coverage bookkeeping — an Observation at most — not a defect against the
contract. I was not persuaded, because the suite's own house standard already pins the exactly-as-
tautological byte-to-enum direction with InlineData for all four ciphers and pins the AES and
Twofish algorithm arms with fixtures; the enum-to-algorithm link for precisely the two ciphers with
no fixture is the one place that standard is not met, and the empirical asymmetry (0 failures versus
24) shows the gap is a hole in an otherwise deliberate net rather than a uniform choice.

---

### F18 — `ReadRsaBodyAsync`'s shipped remark says an edited offset-5 byte "does not fail here", nine lines above the statement that rejects 253 of the 255 possible edits

**Severity:** Low (verifier opinions: Low / Observation / Low) · **Candidate:** C15 · survived 2 of 3
**Location:** `src/Enigma.DataEncryption/Internal/HeaderReader.cs:194-201` (the remark) and `:209-210` (the statement that contradicts it)

**What is wrong.** The remark on `ReadRsaBodyAsync` reads: "It is the header — never the caller — that
selects the unwrap, so an edited byte **does not fail here**: it names a hash the wrap did not use, and
OAEP reports that." Nine lines below, `RsaOaepHashWire.FromWireByte` is the method's **first** statement,
and it throws `DataEncryptionFormatException` for every byte outside `0x02`–`0x04`.

Measured: all 256 values of offset 5 against a real method-`0x03` container give **253
`DataEncryptionFormatException` (thrown at that line), 2 `DataDecryptionException`** (`0x03` and `0x04`,
the two other valid hashes, which do reach OAEP) **and 1 success**. The remark describes 2 of 255 edits
and states the rule unqualified.

**Failure scenario.** A maintainer reading `ReadRsaBodyAsync` to decide where offset-5 validation belongs
is told by the method's own remark that this reader does not validate the byte — and could remove or
weaken the `FromWireByte` call believing OAEP is the real gate, reopening §10's reserved-SHA-1 rule and
§9's undefined-byte row. This is also compiled into the shipped XML.

**Recommended fix.** Change the code doc: an edited byte fails *here* if it is not one of the three
accepted wire values, and reaches OAEP only if it names a different **valid** hash. Note the scope
correction below — this is a code-comment defect only. §3.3 is **not** wrong: it states the rejecting
rule normatively two paragraphs above the sentence in question ("`0x01` (SHA-1) is reserved, not
accepted … a reader must reject it"), and §9 supplies both rows.

**Corrections applied during refutation.**
- *(correctness lens)* Four corrections. (1) DIRECTION IS WRONG — this is not a spec-code
  disagreement. My 256-value probe shows the code matches the spec exactly: 0x00 and 0x05-0xFF give
  "Undefined OAEP-hash byte 0x.. at header offset 5.", 0x01 gives the SHA-1-reserved message,
  0x03/0x04 give the OAEP DataDecryptionException, 0x02 decrypts. That is precisely §9:574 +
  §3.3:181-186 + §10:646. Nothing in the code disagrees with anything in the spec; the finding is
  confined to prose. (2) THE SPEC HALF IS REFUTED. The finder says §3.3:196-198 is "the same overreach
  on the spec side" and that "the two sides are consistent only in being wrong together". §3.3 is not
  wrong: its blockquote at lines 181-182 states "0x00 is never a valid value and a zero-filled header
  cannot parse", and lines 185-186 state in bold "0x01 (SHA-1) is reserved, not accepted (§10). A
  writer must never emit it and a reader must reject it." Both precede the attacked sentence by eleven
  lines in the same subsection. The attacked clause "which §9 already covers" is also accurate as
  written, because §9 carries BOTH the format row (line 574) and the OAEP-unwrap row (line 577). The
  finder dropped the adjacent qualification. Only the six words "makes the OAEP unwrap fail" are
  loose, and the surrounding section supplies the missing case. (3) THE FAILURE SCENARIO IS DEFEATED.
  MalformedContainerSweepTests.cs:221-224 already documents the true behaviour — "an edited selector
  may be caught by the parser, by OAEP or by the AAD depending on the value, and all three are
  documented outcomes" — and AnEditedRsaOaepHashByteIsAContainerError asserts only a generic container
  error via AssertContainerErrorAsync, so there is no per-value format-exception assertion that could
  be "dropped as unreachable", and a maintainer triaging a sweep failure reads that comment, not
  HeaderReader's private remark. (4) Minor citation slips: the remark block is HeaderReader.cs:197-201
  (offending sentence at 199-200), not 194-201; and the throwing FromWireByte call is nine lines below
  it at 209-210, not "three lines below". The 253/2 arithmetic is correct and I reproduced it
  empirically.
- *(spec authority lens)* Three of the finder's supporting statements are wrong. (1) The finder says
  §3.3's sentence "sits two paragraphs from §10's reservation of `0x01`" — it does not. What sits two
  paragraphs above it, inside §3.3 itself, is that section's own normative clause: "**`0x01` (SHA-1)
  is reserved, not accepted** (§10). A writer must never emit it and a reader must reject it"
  (docs/format.md:184-186). §10 is a separate section roughly 450 lines later. This mislocation is
  what makes the finder's "an implementer would be misled" argument look plausible; corrected, it
  fails, because the rejecting obligation is in the same subsection, above the sentence, in "must"
  form. (2) The finder reads "it needs no rule of its own" as denying that §9 has a dedicated row,
  calling it "overreach ... consistent only in being wrong together" with the code. The sentence says
  the opposite — "which §9 already covers" — and "of its own" refers to §3.3 needing no separate rule,
  not to §9 lacking one. There is no contradiction between §3.3 and §9; the only imprecision is that
  the sentence names one of the two outcomes §9 covers. (3) The finder labels this a "spec-code-
  disagreement". The spec and the code agree exactly: RsaOaepHashWire.FromWireByte rejects 0x00, 0x01
  and 0x05–0xFF, which is precisely docs/format.md:574 and §10's "A conforming reader of format
  version `0x10` rejects both." The finder's own evidence demonstrates agreement, not disagreement.
  The finder's arithmetic (for a SHA-256-written container, 2 of the 255 possible edits reach OAEP and
  253 are rejected at parse) does check out, and the quoted source lines are accurate.
- *(reproducibility lens)* Four corrections to the finder. (1) The failure scenario is wrong, and is
  refuted by the very artifact the finder says would be misread:
  MalformedContainerSweepTests.cs:221-225's own doc comment already states the precise three-way truth
  — "an edited selector may be caught by the parser, by OAEP or by the AAD depending on the value, and
  all three are documented outcomes" — and the sweep asserts only that the exception is one of the two
  container types, so there are no per-value format-exception assertions a maintainer could drop as
  unreachable, and a maintainer triaging a sweep failure is corrected by the test's own prose before
  ever opening HeaderReader. (2) The spec half is much weaker than presented: docs/format.md:184-185
  already says of 0x01 "A writer must never emit it and a reader must reject it", the offset-5 row at
  line 163 lists only 0x02/0x03/0x04, and §9:574 is exactly the rule §3.3's "which §9 already covers"
  points at — so a third-party implementer is not led to accept wrong bytes; §3.3's sentence is
  imprecise about the consequence, not contradictory, which is why this is Low and not Medium. (3)
  "Three lines below" is wrong: the remark ends at HeaderReader.cs:201 and FromWireByte is at line
  209, nine lines below (the finder's line citations 194-201, 209-210 and RsaOaepHashWire.cs:93-102
  are themselves all correct — I verified each by line number). (4) The finder missed a third instance
  of the identical overreach: CLAUDE.md:119-120 says "an edited byte fails as an OAEP unwrap error
  rather than needing a rule of its own", so a fix must touch three places, not two. Not a duplicate
  of admitted F08, which concerns RsaDataEncryptionService.cs:204's key-confirmation-mismatch message,
  a different line and a different mechanism.

**Refutation record.**
- **correctness — not refuted:** "I ran all 256 possible offset-5 byte values through a real
  method-0x03 container (fixture rsa-aes.bin with rsa-2048-private.pem) against the prebuilt Release
  library and got exactly 253 DataEncryptionFormatException, 2 DataDecryptionException and 1 success,
  confirming the narrow core of the claim — HeaderReader.cs:199-200's remark "an edited byte does not
  fail here: it names a hash the wrap did not use, and OAEP reports that" is contradicted nine lines
  later at HeaderReader.cs:209 for 253 of the 255 possible edits, and that remark ships in
  Enigma.DataEncryption.xml — but the claim's spec half and its stated direction are both wrong,
  because there is no spec-code disagreement at all (the code implements §9:574, §3.3's blockquote and
  §10:646 precisely) and §3.3 is not "wrong together" with the code: eleven lines above the sentence
  the finder attacks it already states that 0x00 "is never a valid value and a zero-filled header
  cannot parse" and that "0x01 (SHA-1) is reserved, not accepted … a reader must reject it", so the
  finding survives only as a loose internal code remark, at Low."
- **spec authority — **refuted**:** "I reproduced every cited line and then read the surrounding
  sections whole, and the claim collapses on both sides: §3.3 states the rejecting rule normatively
  two paragraphs *above* the sentence complained of ("`0x01` (SHA-1) is reserved, not accepted … a
  reader must reject it" at docs/format.md:184-186, plus the block quote at :178-183, "`0x00` is never
  a valid value and a zero-filled header cannot parse … must map explicitly and must not cast"), and
  the sentence at :196-198 does not deny §9's row — it explicitly points *at* §9, which covers both
  outcomes with two rows (:574 for the invalid byte, :578 for the OAEP unwrap failure), so a third-
  party implementer coding to §9 and §10 builds exactly the reader the code implements; on the code
  side the maintainer harm the finder posits is preempted by the very artifact it names, since
  MalformedContainerSweepTests.cs:217-223 already writes down the correct distinction ("an edited
  selector may be caught by the parser, by OAEP or by the AAD depending on the value, and all three
  are documented outcomes") and HeaderValidationTests.cs:224-260 plus RsaOaepHashWireTests.cs:134-149
  pin the format-exception path by name and across all 256 values — leaving one imprecise clause in
  non-normative rationale prose and one internal XML remark, observable by no reader of the format."
- **reproducibility — not refuted:** "I built a standalone probe against the prebuilt Release DLL,
  encrypted a real method-0x03 container with the committed rsa-2048 fixture PEMs (header prefix EC-
  DE-03-10-01-02, offset 5 = 0x02), then decrypted it 256 times with byte 5 replaced by every possible
  value: exactly 253 values raised DataEncryptionFormatException from RsaOaepHashWire.FromWireByte at
  HeaderReader.cs:209 — the very first statement of ReadRsaBodyAsync — and only 2 (0x03, 0x04) reached
  the OAEP unwrap failure the remark at HeaderReader.cs:197-200 claims for all edits, so the remark's
  unqualified "an edited byte does not fail here" is contradicted by the line immediately below it and
  the claim stands as a documentation-accuracy defect, though only its code-comment half is solid,
  since docs/format.md §3.3 states two paragraphs earlier that "a reader must reject" 0x01, its
  offset-5 table admits only 0x02–0x04, and §9:574 supplies the very rule §3.3's loose sentence defers
  to."

**Strongest surviving counter-argument.** The strongest case for the claim: a comment three lines
above a statement that does the opposite of what the comment says is exactly the small, cheap defect
an adversarial audit exists to catch, and §3.3's rationale sentence propagates the same imprecision
into the normative document — a document that declares itself the contract and whose readers are
told a hand-written implementation must get this right. One could argue that a reader skimming §3.3
for how offset 5 behaves under tampering stops at the paragraph whose bolded lead sentence is on
exactly that topic ("A reader takes the hash from the header, never from its caller"), never
consults §9's table, and so implements only the OAEP-failure path — accepting `0x01` and `0x00` and
letting the unwrap decide, which for `0x00` means a cast-to-enum reader silently unwrapping with the
wrong hash instead of rejecting. That is precisely the "must map explicitly and must not cast"
failure the format warns about, and it costs one clause to close, with no fixture and no format-
version consequence. I was not persuaded, because that hypothetical reader must skip two normative
statements in the same subsection, the §9 error-mapping row that enumerates 0x00/0x01/0x05–0xFF by
value, and the §10 summary — and because the sweep and two named test suites already state and
enforce the distinction on the code side, so the residue is prose polish rather than a defect
against the contract.

---

### F19 — `LimitsValidator.ValidateEncapsulationLength`'s XML places its field at "header offset 18" and calls it "a method-`0x04` header"; the hybrid calls the same method for a field at 22 + N

**Severity:** Low (verifier opinions: Low / Observation / Low) · **Candidate:** C05 · survived 2 of 3
**Location:** `src/Enigma.DataEncryption/Internal/LimitsValidator.cs:52-57` (and `:45-50` for the sibling); second caller at `src/Enigma.DataEncryption/Internal/HeaderReader.cs:310-312`; contradicted by `docs/format.md:248` (§3.5) and `Internal/FormatLayout.cs:117-118`

**What is wrong.** `ValidateEncapsulationLength`'s summary says it "Validates the encapsulation length of
a method-`0x04` header" and its `<param>` says "The value read from header offset 18". Both are true of
method `0x04` and false of method `0x05`, which calls the same method for a field §3.5's table puts at
**22 + N**. The sibling `ValidateWrappedKeyLength`'s summary likewise names only method `0x03` though the
hybrid calls it too (its *offset* of 18 happens to be right for both).

Confirmed against the committed `hybrid-aes.bin`: the `Int32` LE at offset 18 is `N` = 256 (the
wrapped-secret length) and the encapsulation length `M` = 1568 sits at 22 + N = 278; zeroing bytes
`[18,22)` yields "Header field 'RSA wrapped-key length' is 0…" while zeroing `[278,282)` yields "Header
field 'ML-KEM encapsulation length' is 0…".

The staleness mechanism is visible in git: `FEATURE-5A30` (`d590077`) added the second caller **without
touching `LimitsValidator.cs` at all**, while `FEATURE-0D64` (`3443bcb`) hand-edited this very file's
sibling from "offset 17" to "offset 18" — proving these offsets are maintained as accurate spec
cross-references rather than loose prose, which is what makes the omission a defect rather than a style
quibble.

**Failure scenario.** A maintainer adding a sixth method, or re-deriving the hybrid's offsets from the
validator's documentation rather than from §3.5, is told the encapsulation length lives at offset 18. It
does not, for the one method that has two length fields. Nothing a consumer or third-party implementer
can observe is wrong — hence Low, and the spec-authority verifier refuted it as a PHASE04-class stale
comment.

**Recommended fix.** Change the code doc: widen both summaries to name their real callers and state the
offset per method (18 for `0x03`/`0x04`; 18 and 22 + N for `0x05`), or drop the absolute offsets and cite
§3.3/§3.4/§3.5 instead.

**Corrections applied during refutation.**
- *(correctness lens)* Three corrections. (1) Finder D's quoted evidence is not reproducible against
  the committed fixture: D writes "`[22+N..26+N) M = 00 03 00 00 => 768`", but hybrid-aes.bin has
  parameter-set byte 0x03 (ML-KEM-1024), N = 256 and M = 1568 (bytes 20 06 00 00) at offset 278. D's
  number is only obtainable from a self-generated ML-KEM-512 hybrid container; it is arithmetically
  self-consistent but is not the fixture's bytes. Finder DIMENSION I's probe numbers (256 at offset
  18, 1568 at 278) match mine exactly. (2) The claim's "Direction: spec-code-disagreement" is a
  mislabel. The spec and the executing code agree perfectly —
  FormatLayout.HybridEncapsulationLengthOffset(N) => 22 + N, pinned at 278 for N=256 by
  FormatLayoutTests.cs:109, and the validators take a bare int and never index a header. The
  disagreement is strictly between an internal XML doc comment and docs/format.md, i.e. a stale-
  comment defect, not a conformance defect. (3) The claim understates what is already documented
  correctly: HeaderReader.cs:281-289's own <remarks> on ReadHybridBodyAsync explicitly states that
  both lengths are "bounded ... by the same two caps methods 0x03 and 0x04 use: they are the same two
  quantities, so §8 gives the hybrid no caps of its own". So the hybrid's reuse of these validators is
  documented at the call site; only LimitsValidator's own two doc comments are narrow/stale. This is
  also not a duplicate of the two stale XML comments already forwarded to PHASE04
  (EncryptedDataInspector.cs:32-33, HybridKeyCombiner's remarks) — it is a third, distinct site.
- *(spec authority lens)* (1) The claim's Direction, "spec-code-disagreement", is wrong and
  inverted. Nothing in docs/format.md is contradicted by the code. §3.3 (offset 18, wrapped-key length
  N), §3.4 (offset 18, encapsulation length N) and §3.5 (offset 18 wrapped-secret N, offset 22 + N
  encapsulation M) all match HeaderWriter/HeaderReader/FormatLayout exactly, and I confirmed
  FormatLayout.HybridEncapsulationLengthOffset(N) => HybridWrappedSecretLengthOffset(18) + 4 + N = 22
  + N. The disagreement is between an internal XML comment and the code's own second caller — a
  comment-staleness item, not a conformance item. The finder cited §8 as supporting the claim; §8 in
  fact defeats it, since it is the normative clause that says the hybrid deliberately reuses these two
  caps. (2) Finder DIMENSION I's "Both statements are false for one of the method's two callers"
  overstates. Both statements are TRUE for the 0x04 caller and merely INCOMPLETE for the 0x05 caller;
  neither asserts anything the spec contradicts. Likewise the `<param>` text describes provenance
  loosely in both cases: the argument actually passed is `encapsulation.Length` / `wrappedKey.Length`
  (the length of the array ReadLengthValueAsync returned), not the raw Int32 re-read from the header.
  (3) Finder D's "real container" evidence is wrong. D reports the hybrid's field as "[22+N..26+N) M =
  00 03 00 00 => 768". I read both committed hybrid fixtures with python3/struct: hybrid-aes.bin and
  hybrid-twofish.bin both have parameter set 0x03 (ML-KEM-1024), N@18 = 256 and M@278 = 1568 (0x20
  0x06 0x00 0x00). No committed hybrid container has M = 768. Finder DIMENSION I's numbers (256 /
  1568) are the correct ones. (4) The finder's failure scenario is not reachable as written: a
  maintainer who patches bytes [18,22) of a hybrid file gets "Header field 'RSA wrapped-key length' is
  0..." — a message naming the field they actually hit — so the mistake self-corrects on the first run
  rather than surviving to a wrong conclusion.
- *(reproducibility lens)* (1) Finder D's evidence is wrong on the numbers: it quotes the hybrid
  encapsulation-length field as "00 03 00 00 => 768". No committed hybrid fixture reads that — both
  hybrid-aes.bin and hybrid-twofish.bin are 1927 bytes with parameter-set byte 0x03 (ML-KEM-1024),
  N=256 at offset 18 and M=1568 (bytes 20 06 00 00) at offset 278. Finder DIMENSION I's numbers
  reproduce exactly; finder D's do not, so D's "verified against a real container" line should not be
  quoted in the report. (2) The <param> text is loose even for its documented method 0x04: the
  argument actually passed is `encapsulation.Length` — the length of the array returned by
  tee.ReadLengthValueAsync — not "the value read from header offset 18"; the two coincide for 0x04,
  but the parameter is a length, never a byte position. (3) The direction label "spec-code-
  disagreement" overstates it: docs/format.md §3.4/§3.5/§8 and the code agree on every offset, cap and
  behaviour; the disagreement is between the spec and a code comment. (4) The claim is confined to
  these two members — I checked the siblings and ValidatePbkdf2Iterations ("offset 33") and
  ValidateArgon2 ("33 / 37 / 41") match §3.1/§3.2 exactly. (5) The stale sentence is emitted verbatim
  into the generated Enigma.DataEncryption.xml (line 1333-1334 of bin/Release/net10.0), which is
  packed with the library, though internal members never surface in a consumer's IntelliSense.

**Refutation record.**
- **correctness — not refuted:** "I read LimitsValidator.cs:45-57, HeaderReader.cs:220/259/308/312,
  FormatLayout.cs:105-121 and docs/format.md §3.3/§3.4/§3.5 in full, and parsed the committed fixture
  hybrid-aes.bin byte-for-byte (prefix ec de 05 10 01 03; Int32 LE at offset 18 = 256 = the wrapped-
  secret length N; Int32 LE at offset 22+N = 278 = 1568 = the encapsulation length M; 42+N+M = 1866
  header bytes of 1927): the claim stands as a code-doc defect, because ValidateEncapsulationLength's
  XML says "the encapsulation length of a method-0x04 header" whose value is "read from header offset
  18" while HeaderReader.ReadHybridBodyAsync calls the very same method for method 0x05, where §3.5's
  table and FormatLayout.HybridEncapsulationLengthOffset(N) both put that field at 22+N and offset 18
  holds a different field — and git confirms the staleness mechanism exactly, since FEATURE-5A30
  (d590077) added the second caller without touching LimitsValidator.cs at all while FEATURE-0D64
  (3443bcb) hand-edited this very file's sibling "offset 17" to "offset 18", proving these offsets are
  maintained as accurate spec cross-references rather than loose prose."
- **spec authority — **refuted**:** "I read docs/format.md §3.3/§3.4/§3.5/§8 and the code end to end
  and found no spec-code disagreement at all: every cited spec clause is correct (0x03 and 0x04 put
  their length field at 18, 0x05 puts its second one at 22 + N), the code's behaviour matches, and §8
  normatively and explicitly licenses exactly the sharing the finder calls undocumented ("The hybrid
  method (§3.5) introduces no cap of its own... the same two caps apply to them, and both are checked
  before either buffer is allocated") — the sole defect is that two `<summary>`/`<param>` lines on an
  `internal` helper were not widened when FEATURE-5A30 added a second caller, which no reader of the
  contract can observe, which the call site's own remarks (HeaderReader.cs:282-291) and
  FormatLayout.HybridEncapsulationLengthOffset's `<returns>22 + N</returns>` already state correctly,
  so this is a stale-comment item of exactly the class PHASE01 already forwarded to PHASE04, not a
  PHASE02 conformance finding."
- **reproducibility — not refuted:** "I reproduced the claim end-to-end with my own probe against
  the prebuilt Release DLL and the committed fixture hybrid-aes.bin — the Int32 at offset 18 is the
  wrapped-secret length N=256 and the encapsulation length M=1568 sits at 22+N=278, so zeroing bytes
  [18,22) yields "Header field 'RSA wrapped-key length' is 0…" while zeroing [278,282) yields "Header
  field 'ML-KEM encapsulation length' is 0…" — which confirms that LimitsValidator.cs:52-53's
  "Validates the encapsulation length of a method-0x04 header" / "The value read from header offset
  18" is factually wrong for HeaderReader.ReadHybridBodyAsync (HeaderReader.cs:312), the method's
  second caller, and that ValidateWrappedKeyLength's summary (line 45) names only 0x03 though
  HeaderReader.cs:308 calls it for 0x05; the claim stands, but only as a stale internal doc comment —
  docs/format.md, FormatLayout.HybridEncapsulationLengthOffset(N) => 22 + N and the runtime behaviour
  all agree, so nothing a consumer or a third-party implementer can observe is wrong."

**Strongest surviving counter-argument.** Nothing in the normative contract is wrong: docs/format.md
is correct, the wire bytes are correct, the caps are correctly applied to both hybrid length fields,
and the runtime error message names the right field for the right offset — I proved that myself. The
defect is one sentence in an XML comment on an `internal static` method that no consumer, no third-
party implementer, and no test can observe, and it is immediately contradicted by two things sitting
a few lines away: FormatLayout.HybridEncapsulationLengthOffset(N) => 22 + N (pinned at 278 by
FormatLayoutTests.cs:109) and the exception text itself. The finder's failure scenario requires a
maintainer to trust an internal implementation comment over the normative spec, over FormatLayout,
and over the error message their own tamper produced — and the moment they patch bytes [18,22) they
get "RSA wrapped-key length", which tells them precisely what they hit. The audit has moreover
already ADMITTED and forwarded two stale-XML-comment items to PHASE04
(EncryptedDataInspector.cs:32-33, HybridKeyCombiner's remarks); this is a third instance of the same
housekeeping class, arguably a batch item rather than a finding, and the "Direction: spec-code-
disagreement" framing dresses a comment typo as a contract violation.

---

# Observations — PHASE02

Informational. **These do not become phases of the `CODE-REVIEW` item.** O06 and O07 were put through
the same three-lens refutation and reached 1 of 3; O08–O12 were proposed by their finder as Observations
and, on PHASE01's O04/O05 precedent, went to this section without refutation — each is flagged as such.

**O06 — §8's "both are checked before either buffer is allocated" is false of the hybrid, and
unsatisfiable by any conforming reader.** (Candidate C04, 1/3 — reproducibility not refuted at Low;
correctness and spec authority refuted.) `docs/format.md:548`, `Internal/HeaderReader.cs:306-312`.
Measured with a counting stream over a non-seekable input: a method-`0x05` header declaring `N` = 4,096
(legal) then `M` = 999,999 (over cap) pulls **4,122 bytes and has Enigma.Core allocate and fill the full
4,096-byte wrapped-secret array before the `M` cap is ever evaluated**; an `N`-over-cap header stops at 22
bytes. So the sentence is literally false. **Why it did not become a finding:** the strict reading is
foreclosed by the spec's own normative sentence at `docs/format.md:525` — "Decryption **does not require a
seekable input stream**: the header is read forward, once" — which makes checking `M` before allocating
`N`'s buffer impossible for *any* conforming reader, since `M`'s length field lies at 22 + `N`, physically
after the bytes in question. And the difference has no consequence: a verifier's third probe showed an
attacker maximising allocation picks two in-range lengths and forces the full sum-of-caps 8,234 bytes under
*either* ordering, so §8's actual denial-of-service bound is identical. What remains is one subordinate
clause that should read "each is checked before its own buffer is allocated".

**O07 — §9's "requires a key it does not have" is an overstatement for the ML-KEM parameter-set byte.**
(Candidate C07, 1/3 — correctness not refuted at Low; spec authority and reproducibility refuted.)
`docs/format.md:634-637`, `Internal/HeaderReader.cs:251-259` and `:300-312`. §9's closing paragraph
justifies a header-only reader passing an edited selector through by saying "detecting *that* edit is the
AAD's job (§5) and **requires a key it does not have**". For the parameter-set byte that is not quite
true: §3.4 fixes the encapsulation length *exactly* from the parameter set (768 / 1,088 / 1,568), so a
lone edit of offset 5 is detectable by a key-free two-integer comparison. Reproduced: the inspector
reports `ParameterSet=MLKem512 EncapsulationLength=1568`, a pair §3.4 says cannot exist, and on a
synthetic header even `EncapsulationLength=1`. **Why it did not become a finding:** the reproducibility
verifier killed the inference by forging a *self-consistent* tamper — offset 5 set to `0x01`, the length
field set to 768 and the encapsulation truncated to 768 bytes — which the proposed cross-check waves
straight through with an identical decrypt failure. So the cross-check detects one class of unaccompanied
corruption, not "that edit", and §9's sentence is right about the general case. The decrypt-side behaviour
is separately licensed by §9's own "Why ML-KEM is asymmetric" note, which names an edited parameter-set
byte as a cause deliberately reported as `DataDecryptionException` (deliberate choice 1, undefeated).
Worth a word of precision in §9; not worth a branch.

**O08 — `CLAUDE.md` credits `FormatConstantsTests` with pinning "the five header lengths"; the real pin
is in `FormatLayoutTests`.** (Finder-proposed Observation; not put through refutation. Forwarded to
PHASE04, which owns `CLAUDE.md`.) `FormatConstantsTests.HeaderLengths_MatchTheSpecification` names no
`FormatLayout` member — it declares its own `private const int CommonPrefixLength = 5`, rebuilds each
length from `DataEncryptionDefaults`, and compares to 53/61/38/38/42. That is a second independent
derivation: it would pass unchanged if `FormatLayout.Pbkdf2HeaderLength` omitted the tag term. The
assertion that actually pins `FormatLayout` is `FormatLayoutTests.TheFiveHeaderLengthsMatchTheSpecification`
(`FormatLayoutTests.cs:30-37`), which `CLAUDE.md` does not mention. **Coverage exists; `CLAUDE.md` is
wrong about where it lives** — which matters only if someone deletes one file believing the other covers
it. The audit lead verified this independently before the fan-out returned.

**O09 — §1.1's little-endian requirement is pinned only in a way a little-endian host cannot distinguish
from host-order encoding.** (Finder-proposed Observation; not put through refutation.)
`tests/…/Internal/HeaderGoldenBytesTests.cs:80-116`. `Int32Fields_AreLittleEndian` and its siblings assert
the emitted bytes on the host they run on, and on a little-endian host `BitConverter.GetBytes` produces
exactly the same bytes — so no test in this repository can tell a §1.1-conforming writer from a host-order
one. **Conformance is nonetheless real and was established by decompilation:** Enigma.Core's `WriteInt` /
`ReadInt` / `WriteIntAsync` / `ReadIntAsync` are literal shift expressions in all three shipped TFMs, not
`BitConverter`, and `HybridKeyCombiner.WriteInt32LittleEndian` likewise. So this is a pinning gap over a
property that currently holds, on the one clause §1.1 itself calls "the single most likely source of a
silent interop defect". The cheap close, if it is worth closing, is to assert the *shift expression*
rather than a byte literal that happens to match on this host.

**O10 — `LimitsValidator`'s XML illustrates the caps with an example the defaults accept.**
(Finder-proposed Observation; not put through refutation.) `Internal/LimitsValidator.cs:9-13` says a header
claiming "two billion Argon2 iterations, **or a gigabyte of Argon2 memory**, must be rejected by arithmetic
rather than survived by computation." `MaxArgon2MemorySizeKb` defaults to 1,048,576 KiB — *exactly* one
gibibyte — and `Validate` rejects only `value > maximum`, so a header claiming a gigabyte of Argon2 memory
is **accepted** and the reader allocates it. The two-billion-iterations half is correct. `docs/format.md:554`
is careful where the code doc is not ("allocating gigabytes", plural, and "exceeds its cap"). Fix the
example, not the cap.

**O11 — the inspector's stream position depends on `CanSeek`, and the contract nowhere says so.**
(Finder-proposed Observation; not put through refutation.) `Services/EncryptedDataInspector.cs:55-56` and
`:69-72`. `ReadHeaderAsync` captures `input.Position` when `CanSeek` and restores it in a `finally`, so a
seekable stream comes back at its original position while a non-seekable one is left at the first payload
byte. §7.2's closing paragraph is the only positioning promise in the contract and §9's final paragraph the
only description of a header-only reader; neither mentions this. The behaviour is well-reasoned and argued
in the interface's XML remarks — a caller probing a file it is unsure about should not have its stream
consumed — so the code should not change; one sentence in §9 would close it.

**O12 — §9's closing sentence enumerates "an edited-but-valid cipher or parameter-set byte" and omits
method `0x03`'s OAEP-hash byte.** (Finder-proposed Observation; not put through refutation.)
`docs/format.md:634-637`. `FEATURE-0D64` added a third valid-but-editable selector after that paragraph was
written, and the inspector treats it identically — `RsaOaepHashWire.FromWireByte` accepts `0x02`/`0x03`/`0x04`
and the inspector reports whichever it found. Unlike the parameter-set byte in O07, this one is **genuinely**
unverifiable without the key (all three hashes are possible for any modulus of 162 bytes or more), so §9's
stated reason applies to it more cleanly than to the field the sentence does name. Extend the enumeration to
"cipher, OAEP-hash or parameter-set byte".

**Line endings.** No CRLF/LF inconsistency was observed in any file read across the ten finder slices.
Recorded here because the house rule makes anything about line endings an Observation and never a finding.

---

# Considered and refuted — PHASE02

Suspected, investigated, and found **not** to be defects — all seven reached 0 of 3. Recorded so the next
reviewer does not repeat the work, and so the reasoning can be argued with. Several of these were
*expensive* to kill and the killing produced results worth keeping; where that happened it is noted.

**R08 — "The encrypt path validates cost parameters only at `> 0`, never against §8's caps, so the library writes containers its own default reader rejects — and §7.1 step 1's 'cost parameters in range' makes that a spec clause the code does not honour."** (C01, refuted 3/3.)

**This was the most-raised candidate of the phase — 4 of 10 finders, one at High — and it is a re-dressing
of PHASE01's O01.** The underlying behaviour is real and was reproduced again: `iterations: 10_000_001`
encrypts happily and writes `81 96 98 00` at offset 33, then fails its own default-limits decrypt. What
PHASE02 added was the argument that §7.1 step 1's "cost parameters in range" imports §8's caps as a
*write-side* obligation. All three verifiers rejected that reading, on the document's own structure:
§7.2 step 3 names "`DataEncryptionLimits` (§8)" explicitly when the caps are meant while §7.1 step 1
pointedly does not; every operative sentence in §8 is about a *field* in a *header* read by a *decrypt
attempt*, and its declared consequence is a "format error", which §9 glosses as "this is not a container I
can parse" — a diagnosis no argument to `EncryptAsync` can attract, because no container exists yet; the
spec binds a writer explicitly exactly once and does so in unmistakable words ("A writer must never emit it
and a reader must reject it", `docs/format.md:185`), with no such sentence anywhere in §8; and "in range"
sits alongside three siblings ("streams non-null, credential non-null/non-empty, cipher defined") that are
all pure argument checks mapping to §9's `ArgumentOutOfRangeException` row. A correction worth recording:
the finders' claim that nothing warns a caller the two ranges differ is **false** — `DataEncryptionLimits`'
class summary is "Upper bounds applied to the cost and length fields **read from a container header**",
each of its six properties says "accepted from a header", and `docs/guides/password-based.md:43` and `:60`
state the encrypt-side range and the reader-side scope separately. A further tell: the four finders split
three ways on *which side to change*, one arguing explicitly that binding the writer to `Default` "would be
the wrong side" — which is the signature of an ambiguity, not of the offset/size/constant disagreement the
document's preamble is about. **Reporting this would have re-admitted a PHASE01 observation and sent a
maintainer to change a documented, deliberate scoping.**

**R09 — "§5's 'Any edit to any header byte is an authentication failure' is contradicted by §6.2 and by the code: for the password methods no header edit ever surfaces as an authentication failure."** (C11, refuted 3/3.)

The sweep behind this is real — all eight single-bit flips at each of the 53 header offsets of a real
method-`0x01` container gave 47 `DataEncryptionFormatException`, 377 key-confirmation
`DataDecryptionException` and **zero** GCM authentication failures. But two verifiers independently ran the
experiment the finder never ran: **edit a header byte and then repair `kcTag` under the unchanged data
key**. At that point the very same edits *do* produce the GCM authentication failure
(`DataDecryptionException` wrapping `CryptographicException`, "The container failed authentication: the
payload or the header has been altered, or the container is truncated"), one verifier having first
re-derived `K` and `kcTag` independently and matched the container's tag byte-for-byte. **§5's AAD binding
is real, reachable and implemented**; the sweep measured only which of two deliberately overlapping checks
fires first, an ordering §7.2 steps 5→6 mandates normatively and §6.3 states outright. §5's own next
sentence disambiguates it ("all produce the same outcome: decryption fails"), and §9 maps both checks to
the same exception type. This refutation is worth keeping as a **positive** result: it is the first direct
demonstration in this audit that the AAD binding is not merely present but reachable.

**R10 — "§3.5.1's parenthetical '(bytes 18 through 26 + N + M)' contradicts the clause it restates and makes the combiner transcript one byte too long."** (C13, refuted 3/3.)

Refuted 3/3, and the reproducibility verifier's probe is the decisive part. On a real hybrid container
(RSA-2048 + ML-KEM-512, `N` = 256, `M` = 768, tag at 26 + `N` + `M` = 1,050) the half-open slice
`[18, 1050)` — 1,032 bytes — reproduces the wire `kcTag` byte-for-byte and decrypts the payload, while the
"inclusive" slice `[18, 1050]` is 1,033 bytes whose extra byte is `0x88`, **the tag's own first byte**. So
the feared alternative reading is not an alternative construction at all but a *circular* one
(T → K → kcKey → kcTag), impossible for any writer to implement and explicitly ruled out by §5's numbered
non-circularity argument. The document also disambiguates the number twice over: the bolded operative
clause in the same sentence says "up to, but **not including**, the key-confirmation tag", T's normative
definition is the display formula three lines above (`LE32(N) ‖ wrappedRsaSecret ‖ LE32(M) ‖ encapsulation`,
unambiguously 8 + `N` + `M` bytes), and §6 independently fixes this document's convention for exactly this
expression — "every header byte from offset 0 up to, but not including, the tag — i.e. … 26 + `N` + `M` for
the hybrid" — a count, not an included index.

**R11 — "`HeaderReader`'s `catch (InvalidOperationException)` reports 'A container header length field is negative or above its permitted maximum' for PBKDF2 and Argon2 containers, which carry no length field at all."** (C14, refuted 3/3.)

True as stated, and refuted 3/3 as a **duplicate of PHASE01's F05**. The quotations all check out — the
blanket catch, the fixed message, the absence of any `ReadLengthValueAsync` call in the two password body
readers, and §3.1/§3.2's fixed 53- and 61-byte tables with no length-value field. But a verifier's probe
showed the trigger is not shape-specific: a disposed input stream throws `ObjectDisposedException` on the
**very first read** — the two magic bytes, before the method byte is consumed — so the identical message is
emitted for `rsa-aes.bin` too, a shape that *does* carry a length field. The defect is therefore "the
blanket catch reclassifies caller-stream failures as container corruption", which is verbatim F05, with the
same trigger class, the same mechanism and the same fix (narrow the catch to the length-value reads). C14
adds only a shape-specific wording detail on top. **PHASE05 should fold the wording detail into F05 rather
than carry it separately.**

**R12 — "The inspector reports an edited method byte as found and returns a `HeaderLength` that is not the offset of the first payload byte."** (C16, refuted 3/3.)

The relabelling reproduces (`hybrid-aes.bin` with byte 2 set to `0x04` inspects as `method=MLKem`,
`HeaderLength=294` against a true 1,866), but a verifier's counter-probe killed the claim's premise: editing
**only** the wrapped-key-length field at offset 18 of an untouched `rsa-aes.bin` produces exactly the same
defect (`HeaderLength=138` against a true 294). A wrong `HeaderLength` is therefore a universal property of
every unauthenticated header field, not anything special about the method byte — and §9's closing paragraph
licenses precisely that, with a reason that applies verbatim given §5's "Any edit to any header byte is an
authentication failure". §2.2's "Each service reads only its own method byte" is scoped to *services*, and
the code honours it exactly (`DataEncryptionFormatException: Container was produced by the MLKem method
(byte 0x04); this service reads Hybrid (byte 0x05) only.`). The finder's proposed §3.4 cross-check would
also break the one edit §9 names explicitly as permitted to pass through.

**R13 — "A structurally impossible RSA wrapped-key length — below §3.3's `k >= 2·hLen + 34` for the hash the header itself names — is reported as `DataDecryptionException` rather than `DataEncryptionFormatException`."** (C17, refuted 3/3.)

Refuted 3/3, and the reproducibility verifier's numbers are what settle it: patching offset 18 to
`N` = 98, 130, 162 and 255 — **every value that would pass the proposed floor** — produces the
byte-identical `DataDecryptionException` with the byte-identical message. The proposed check would relabel
97 of the 255 wrong lengths and leave the claimed operator harm entirely intact. On the contract side,
§5:406-407 names this precise mutation and prescribes this precise outcome ("Flipping the cipher byte,
lowering the iteration count, swapping a salt or **truncating the wrapped key** all produce the same
outcome: decryption fails"); §9's table assigns "RSA OAEP unwrap failure" to `DataDecryptionException` with
no length carve-out and scopes the reader's length check to "exceeds `DataEncryptionLimits`, or is `<= 0`";
and §3.3's `k >= 2·hLen + 34` is *encrypt-side* prose about the caller's key-size choice, which §9's own
note explicitly assigns to the wrap side while recording that pre-validating modulus size "is not
available: Enigma.Core exposes no modulus-size accessor". Note this is the neighbouring field to **F11** and
the two must not be conflated: F11 survives because the exception escapes the two container types entirely,
which no §9 row licenses; C17 fails because `DataDecryptionException` is exactly what §9 prescribes.

**R14 — "§4's normative 'GCM padding | none (`PaddingScheme.None`)' row is both unpinned by any test and unobservable from the container bytes."** (C18, refuted 3/3.)

The mechanism is real and all three verifiers confirmed it by decompilation: Enigma.Core's
`BlockCipherService.BuildCipher` returns `new BufferedAeadBlockCipher(new GcmBlockCipher(engine))` for
`BlockCipherMode.Gcm` and **never touches the `padding` argument**, so all five `PaddingScheme` values yield
byte-identical output. But both halves of the claim fail. §4's row states a *format* property — "no
padding", i.e. length-preserving ciphertext — and that **is** wire-observable and **is** pinned by name in
four suites (`PasswordRoundTripTests.cs:56`, `RsaRoundTripTests.cs:182`, `MLKemRoundTripTests.cs:67`,
`HybridRoundTripTests.cs:93`, each documented "no padding, no trailer (docs/format.md §4)") asserting
`HeaderLength + plaintext.Length + 16 == container.Length` across empty, 1-byte, 1,000-byte, 8 MiB and
45-byte payloads; an empty payload yielding exactly 16 bytes is impossible under any padding scheme. And
"unpinnable" is false too: a verifier injected a recording `IBlockCipherServiceFactory` through the
**public** `Pbkdf2DataEncryptionService` constructor and read the argument straight back
(`Encrypt mode=Gcm padding=None mac=128 aadLen=53`). What is left is that no existing test asserts an inert
argument whose spec row restates GCM's own definition.

---

# Coverage statement — PHASE02

## What was examined

**Read in full**, by at least one finder and usually several: `docs/format.md` in its entirety (all 660
lines, §§1.1–10, every table row and every block quote); `Internal/FormatLayout.cs`, `HeaderWriter.cs`,
`HeaderReader.cs` (including `TeeStream`), `MLKemParameterSetWire.cs`, `RsaOaepHashWire.cs`,
`CipherResolver.cs`, `LimitsValidator.cs`, `ParsedHeader.cs`, `HybridKeyCombiner.cs`, `KeyConfirmation.cs`,
`PayloadCipher.cs`, `PasswordCredential.cs`; `EncryptedDataHeader.cs`, `Cipher.cs`, `EncryptionMethod.cs`,
`DataEncryptionDefaults.cs`, `DataEncryptionLimits.cs`; `Services/EncryptedDataInspector.cs` and the
encrypt/decrypt paths of all five services; `Api/FormatConstantsTests.cs`, `Internal/FormatLayoutTests.cs`,
`HeaderGoldenBytesTests.cs`, `HeaderValidationTests.cs`, `KeyConfirmationTests.cs`,
`MLKemParameterSetWireTests.cs`, `RsaOaepHashWireTests.cs`, `CipherResolverTests.cs`,
`Services/GoldenVectorInventoryTests.cs`, `GoldenVectorPrimitives.cs`, `HybridGoldenVectorTests.cs`;
`docs/plan/FEATURE-0D64.md` and `docs/done/FEATURE-0D64.md` (to establish intent behind the offset-5
change).

**Reproduced by execution.** Every finder that could build a probe did. Between them: real containers
generated for all five methods and hexdumped field by field against the §3 tables; all fourteen committed
fixtures parsed at the spec's offsets; RSA containers built at 776/784/792/800/1016/1024/1025/1032/1040/
1088/1152/1280/1536/2048/4096 bits under all three OAEP hashes; ML-KEM containers at all three parameter
sets; a **3,281-line byte-edit sweep** recording the exception type and message from both `DecryptAsync`
and `ReadHeaderAsync` for every value of every selector byte on every method; a counting-stream probe
measuring bytes consumed before each cap fires; container-length measurement at L = 0, 1, 17, 45, 1,000,
5,000 and 8 MiB for all five methods; and two **mutation experiments** on scratchpad copies of `HEAD`
(`git archive`), never on the repository.

**Two independent spec-only implementations were written**, which is what makes the reverse-direction claim
in this coverage statement mean something: a Python header parser and a BCL-only C# decryptor
(`Rfc2898DeriveBytes`, `HMACSHA256`, `AesGcm`, `RSA.ImportFromPem`, plus OpenSSL 3.6.3 `ARGON2ID` for §3.2),
both written from `docs/format.md` alone with no reference to the library's source, plus a spec-only
*writer* whose output was handed back to the library's readers.

**Dependency behaviour was settled by decompilation** (`ilspycmd`, `DOTNET_ROOT=$HOME/.dotnet`) wherever a
conclusion turned on it: Enigma.Core's `StreamExtensionsInt32` on **all three shipped TFMs**,
`StreamExtensionsLengthValue`, `StreamExtensionsBytes`, `StreamReadHelpers`, `PublicKeyService` (including
its private `Transform`), `BlockCipherService`, `MLKemService`, `GcmMacSize`; and from BouncyCastle 2.6.2,
`OaepEncoding.DecodeBlock` and `RsaCoreEngine.GetOutputBlockSize`.

## Verified clean — attacked and found sound

Recorded so a later reviewer need not redo the work. **This is the larger half of PHASE02's result**: the
format machinery is, offset for offset, what the document says it is.

- **Every offset in §§3.1–3.5, on real bytes and on committed fixtures.** PBKDF2 `0(5)→5(12)→17(16)→33(4)→
  37(16)→53`; Argon2 `…33(4)→37(4)→41(4)→45(16)→61`; RSA `0(5)→5(1)→6(12)→18(4)→22(N)→22+N(16)→38+N`;
  ML-KEM identically at `38+N`; hybrid `…18(4)→22(N)→22+N(4)→26+N(M)→26+N+M(16)→42+N+M`. Confirmed on
  generated containers for every method and parameter set, and on `hybrid-aes.bin` (`N`@18 = 256,
  `M`@22+N = 1,568, tag@26+N+M = 1,850, header = 1,866) and `mlkem-1024-aes.bin` (`N`@18 = 1,568,
  tag@1,590, header = 1,606). `EncryptedDataHeader.HeaderLength` equals the true first-payload-byte offset
  for all five shapes.
- **§1.1's little-endian rule holds on a big-endian host.** Enigma.Core's `WriteInt`/`ReadInt` (and the
  async and unsigned variants) decompile to literal shift expressions — `(byte)value`, `(byte)(value >> 8)`,
  … and `array[0] | (array[1] << 8) | …` — **byte-identical across net10.0, net8.0 and netstandard2.0**, not
  `BitConverter`. `ReadLengthValueAsync` delegates to `ReadIntAsync`, so the length prefixes inherit it, and
  `HybridKeyCombiner.WriteInt32LittleEndian` is explicit too. §1.1's own worked example (600,000 →
  `C0 27 09 00`) is correct and is pinned three times, including `Pbkdf2GoldenVectorTests.cs:156` asserting
  `container[33..37]`. The clause the spec flags as its likeliest silent interop defect is sound.
- **The two wire mappings are explicit in both directions and exhaustively rejecting.** `0x00` and
  `0x04`–`0xFF` for the parameter set, and `0x00`, the reserved `0x01` and `0x05`–`0xFF` for the OAEP hash,
  all raise `DataEncryptionFormatException` — verified across all 256 values of each, on real containers.
  Both are pinned against spec literals by their own suites, in both directions.
- **The rejection matrix is complete.** All 255 non-`0xEC` values at offset 0 and all 255 non-`0xDE` at
  offset 1, on all five methods (2,550 cases); method byte `0x00` and `0x06`–`0xFF`; a valid method byte
  handed to the wrong service; version `0x00`, the reserved `0x01`–`0x0F`, and `0x11`–`0xFF`; cipher `0x00`
  and `0x05`–`0xFF`; length and cost fields at 0, negative and above cap — every one a
  `DataEncryptionFormatException`, from `DecryptAsync` and `ReadHeaderAsync` alike.
- **The inspector never raises `DataDecryptionException`, on any input tried.** §9's closing promise holds.
- **§5's "the AAD is exactly the header, and exactly once" is true by measurement**, not by reading: for all
  five methods at L = 0, 1, 17, 1,000 and 5,000 the container is **exactly** `HeaderLength + L + 16` bytes,
  25 of 25 exact. There is no trailing byte, no alignment, no framing and no length prefix the spec does not
  describe, and the GCM payload really is ciphertext ‖ 16-byte tag with the tag last.
- **§5's AAD binding is reachable, not merely present.** Repairing `kcTag` after a header edit produces the
  GCM authentication failure (see R09) — the first direct demonstration in this audit that the two checks
  are genuinely layered rather than one masking the other.
- **§7.2's closing claim holds.** The header read is single-pass and forward-only for all five methods over
  a genuinely non-seekable stream (`CanSeek => false`, `Position` and `Length` throwing, 1-byte reads), with
  bytes consumed from a counting stream equal to `HeaderLength` — **no over-read by even one byte**. The
  encrypt direction requires no seekable output stream either.
- **§7.1 step 3's "both public-key operations precede any write" holds** for methods `0x03`, `0x04` and
  `0x05`: a bad public key leaves `output.Length == 0`.
- **§6's five `headerBytesBeforeTag` numbers are arithmetically correct** against the §3 tables
  (53−16 = 37, 61−16 = 45, 38+N−16 = 22+N twice, 42+N+M−16 = 26+N+M), and §3.5.1's transcript slice
  `[18, 26+N+M)` is exactly 8 + `N` + `M` bytes (see R10).
- **All thirteen rows of §4 trace to the file:line that establishes them**, and `GcmMacSizeBits` is pinned
  equal to Enigma.Core's `GcmMacSize.MaxBits` rather than to the number 128.
- **§3.4's per-parameter-set sizes are right** — 768 / 1,088 / 1,568, measured directly, matching FIPS 203.
- **§3.3's `N` = modulus size independently of the hash** — verified for 1024/2048/4096 × SHA-256/384/512.
- **§3.3's `k >= 2·hLen + 34` arithmetic is right** (98 / 130 / 162), and no public decrypt overload
  anywhere — including the file-path extensions — takes an `RsaOaepHash`.
- **`FormatLayout`'s arithmetic is pinned directly** against spec literals (`FormatLayoutTests.cs:30-37`),
  along with the magic, the 5-byte prefix and the hybrid length-field offsets 18 / 278 / 534.
- **All fourteen committed fixtures are conformant** to the document, parse at exactly the spec's offsets,
  and decrypt to the committed golden plaintext. Encrypting the same plaintext twice produces containers
  differing only in the documented random fields.
- **A spec-only writer's output is read correctly by the library** for the password methods and for RSA
  under MGF1 = the selected hash — which is exactly how F12 was isolated.

## What PHASE02 consciously did not examine

- **Test-suite quality as a dimension** — PHASE03's. F17 and O08/O09 touch pinning because a pinning gap
  over a *normative wire clause* is a §2.4/§1.1 conformance question, but PHASE02 ran no coverage
  measurement, judged no test for tautology beyond the specific clauses above, and did not audit the
  malformed-input sweep's construction. The two mutation experiments were narrowly scoped to the cipher
  mapping and were run on scratchpad copies; **no `src/` file was mutated in the repository, even
  temporarily** — PHASE02 does not have PHASE03's mutation carve-out and did not need it.
- **Golden-vector provenance** — PHASE03's. PHASE02 confirmed the fixtures are *conformant* and that they
  decrypt; it did not audit whether each was computed by a genuinely external oracle.
- **The public API surface, guides, packaging and `CLAUDE.md` as documents** — PHASE04's. F13, F14, F18 and
  F19 are XML-doc defects reported here because each contradicts a specific `docs/format.md` clause, which
  is PHASE02's dimension; the general XML-docs-as-contract sweep is PHASE04's, and O08 is forwarded there.
- **Cryptographic correctness** — PHASE01's, and not revisited. PHASE02 took PHASE01's *verified clean* list
  as settled and primed every agent with it.
- **The `netstandard2.0` polyfill paths and any non-x64 or big-endian host.** The endianness conclusion rests
  on decompiled source being byte-identical across the three TFMs, **not** on execution on a big-endian
  machine; O09 records that no test could distinguish the two either.
- **F11's boundary was established on one platform.** The escape window `k ∈ [98, 128]` and the decoder
  condition `(modBits − 1)/8 < 2·hLen` were pinned by execution on linux-x64 against BouncyCastle 2.6.2; a
  different BouncyCastle version could move it.
- **Enigma.Core and BouncyCastle beyond the specific behaviours a finding turned on.** This audit assumes the
  primitives are correct; F11 is the one place it looks inside one, and even there it reports the
  *translation* gap in this library rather than proposing an upstream fix.

## Execution boundary

No file outside `docs/review/`, `docs/roadmap.md`, `docs/plan/` and `docs/done/` was created, modified or
deleted. **No `src/` or `tests/` file was mutated in the repository, even temporarily** — the two mutation
experiments ran on `git archive HEAD` copies inside the session scratchpad. All verification code lives in
the scratchpad and is quoted here rather than committed; no test was added to the suite. `git diff --stat`
against the phase branch point is recorded in `docs/done/FEATURE-F612-PHASE02.md`.
