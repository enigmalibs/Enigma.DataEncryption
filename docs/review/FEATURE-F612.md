# Code Review — Enigma.DataEncryption (pre-v1.0.0)

**Date:** 2026-07-29
**Commit reviewed:** `b1ab2c2918cb569fcec1de9ef7bdce92b7039972` (branch `develop`, at the merge of
`feature/feature-0d64-rsa-oaep-hash`)
**Work item:** `FEATURE-F612` — full adversarial pre-release audit, report only. See
`docs/plan/FEATURE-F612.md`.
**Status:** PHASE01 complete. PHASE02–PHASE04 append their dimensions below; PHASE05 writes the
executive summary and the release gate, deduplicates across dimensions and recalibrates severity
globally.

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
