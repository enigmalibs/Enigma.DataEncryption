# FEATURE-136E — Legacy decrypt support for Enigma.Cryptography.DataEncryption files (deferred)

**Status:** TODO — **deliberately deferred; not part of the v1.0.0 release**
**Type:** FEATURE (single-phase)
**Suggested branch:** `feature/feature-136e-legacy-reader`
**Depends on:** FEATURE-11B6 (complete)

## Why this is deferred rather than absent

The decision at planning time was: v1.0.0 reads and writes only the new format, but the architecture
keeps the door open. Concretely, `docs/format.md` reserves format-version bytes `0x01`–`0x0F` for the
predecessor's versions, and the header reader dispatches on the version byte — so this item is an
addition, not a redesign.

It is deferred because a legacy reader **cannot share the new pipeline**. It needs an unauthenticated
header (no AAD), no key-confirmation tag, PKCS#1 v1.5 RSA unwrap, ML-KEM fixed at 1024, and the old
`memoryPowOfTwo` Argon2 semantics. That is a parallel implementation plus its own test suite, for a
need that did not exist when the plan was made.

**If that need never materializes, mark this `ABANDONED` with a reason rather than deleting the row.**

## Objective

Add the ability to **decrypt** files written by `Enigma.Cryptography.DataEncryption` 1.2.0 and earlier.
**Never** to write them.

## Predecessor format, as read from the source

Common prefix: `EC DE` ‖ type ‖ version ‖ cipher — the same shape the new format preserves, which is
what makes version dispatch sufficient.

| Method | Type | Legacy version | Body after the cipher byte |
|---|---|---|---|
| PBKDF2 | `0x01` | `0x01` | nonce(12) ‖ salt(16) ‖ iterations(Int32 LE) |
| Argon2 | `0x02` | `0x01` | nonce(12) ‖ salt(16) ‖ iterations(Int32) ‖ parallelism(Int32) ‖ **memoryPowOfTwo**(Int32) |
| RSA | `0x03` | `0x02` | keyFingerprint(16) ‖ nonce(12) ‖ length-value(wrapped key) |
| ML-KEM | `0x04` | `0x02` | keyFingerprint(16) ‖ nonce(12) ‖ length-value(encapsulation) |

Cipher byte values are unchanged (`0x01`–`0x04`), which is why the new format kept them.

Note the versions differ per method (`0x01` for the password methods, `0x02` for the public-key ones) —
dispatch must be on the **(method, version) pair**, not on the version alone.

## Behaviours that must be reverse-engineered and *verified*, not assumed

Every one of these is a guess until confirmed against `Enigma.Cryptography` 4.3.0 (present in the local
NuGet cache at `~/.nuget/packages/enigma.cryptography/`) **and** against real fixture files. Do not
implement from the table below without verifying each row.

| Unknown | Working assumption | How to verify |
|---|---|---|
| PBKDF2 password `string` → bytes encoding | UTF-8 | Decompile/inspect `Enigma.Cryptography.KDF.Pbkdf2Service.GenerateKey(int, string, byte[], int)` |
| PBKDF2 PRF | HMAC-SHA256 | Predecessor README states PBKDF2-HMAC-SHA256; confirm in source |
| Argon2 memory semantics | `memorySizeKb = 1 << memoryPowOfTwo` | Predecessor docs say `16 → 64 MiB`, consistent with `1 << 16 = 65536` KiB; confirm in source |
| Argon2 variant / version | Argon2id, v1.3 | Predecessor README says Argon2id; confirm in source |
| RSA key-wrap padding | **PKCS#1 v1.5** | `rsaService.Encrypt(key, publicKey)` in the old service — determine which padding that maps to. Use `IPublicKeyService.DecryptPkcs1` or `DecryptOaep` accordingly |
| GCM MAC size | 128 bits | `BlockCipherParametersFactory.CreateGcmParameters(key, nonce)` in the old library |
| ML-KEM level | 1024, fixed | Old service hard-codes `CreateKem1024()` |

## Design

**A separate service, not overloads on the four current ones.** Something like:

```csharp
public interface ILegacyDataDecryptionService
{
    Task DecryptAsync(Stream input, Stream output, /* credential */ …,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);
}
```

Rationale: it keeps legacy code in one clearly-quarantined place, makes the read-only nature obvious in
the type name, and means the four primary services never grow a code path that skips header
authentication.

Requirements:

- **Decrypt only.** No legacy write path, ever.
- The legacy header is **not** used as AAD (the old format did not authenticate it) — pass
  `associatedData: null`. Document why, prominently, so it is never mistaken for a bug.
- There is **no key-confirmation tag**, so wrong-credential detection reverts to the old behaviour:
  fast for RSA if the padding fails, and only at the end of the stream for the password methods and
  ML-KEM. Document this as an inherent limitation of the old format.
- **Apply the `DataEncryptionLimits` caps anyway**, and convert `memoryPowOfTwo` **before** validating,
  so a hostile legacy header cannot allocate `2^31` KiB. This is a genuine hardening improvement over
  the predecessor and costs nothing.
- The old header's 16-byte **key fingerprint** field must be *parsed and skipped*. Do not attempt to
  verify it for RSA: deriving a public key from a PEM private key needs ASN.1 parsing or a direct
  BouncyCastle reference, and adding either purely for a cosmetic pre-check would violate the
  BouncyCastle-isolation invariant's spirit. For ML-KEM the encapsulation key can be sliced out of the
  expanded FIPS 203 decapsulation key if a check is wanted — optional, not required.
- Register in `AddEnigmaDataEncryption()` alongside the rest.

## Test strategy

The distinguishing feature of this item is that it is **verifiable rather than speculative**:

1. Write a small throwaway generator program referencing `Enigma.Cryptography.DataEncryption` 1.2.0
   (in the local NuGet cache) that produces one encrypted file per (method × cipher) with fixed
   credentials and a fixed known plaintext.
2. **Commit those files as test fixtures**, together with the credentials and expected plaintext, and a
   README in the fixture directory recording exactly which package version produced them.
3. Assert exact plaintext recovery for every fixture. This pins the reverse-engineered behaviour
   against ground truth instead of against a reading of the source.
4. Add malformed-input coverage for the legacy shapes, matching the sweep in FEATURE-11B6 PHASE05.
5. Assert that a **new-format** file passed to the legacy service fails cleanly, and that a
   **legacy** file passed to a primary service fails with `DataEncryptionFormatException` naming the
   unsupported version.

The generator program itself is **not** committed — only its output. Record in the completion doc how
it was built so the fixtures can be regenerated.

## Acceptance criteria

1. Every unknown in the table above verified against the real predecessor package, and the finding
   recorded in the completion doc.
2. All four legacy methods decrypt correctly, proven against committed fixtures produced by the actual
   predecessor library.
3. No legacy write path exists anywhere.
4. Limits are enforced on legacy headers, including the `memoryPowOfTwo` conversion before validation.
5. New-format and legacy files are never confused in either direction, asserted by test.
6. `BouncyCastleIsolationTests` still passes — no BouncyCastle reference was added to make this work.
7. `docs/format.md` gains a "legacy formats" appendix documenting the layouts above and the verified
   parameter semantics.
8. Zero-warning Release build; full suite green on both test TFMs.
