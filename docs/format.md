# Enigma.DataEncryption — binary container format

**Format version `0x10`.** Normative specification.

This document is **the contract**. The library and this file must agree on every offset, size and
constant; where they disagree, that is a defect in one of them, not a matter of interpretation. The
golden-vector tests encode this document.

An encrypted container is a **self-describing** byte sequence: a plaintext header carrying everything
a reader needs to decrypt (short of the credential), followed by a single AEAD payload.

```
+---------------------------------------------------+---------------------------+
| header (plaintext, authenticated)                  | GCM payload               |
| magic | method | version | cipher | … | kcTag      | ciphertext ‖ 16-byte tag  |
+---------------------------------------------------+---------------------------+
|<---------- passed in full as GCM AAD ------------->|
```

---

## 1. Conventions

### 1.1 Integer encoding

Every multi-byte integer in the header is a **signed 32-bit little-endian** value (`Int32` LE),
matching `Enigma.Core.Extensions.StreamExtensionsInt32`:

```
data[0] = (byte)value;
data[1] = (byte)(value >> 8);
data[2] = (byte)(value >> 16);
data[3] = (byte)(value >> 24);
```

**This is stated explicitly because it is the single most likely source of a silent interop defect.**
An iteration count of `600000` (`0x000927C0`) is written as the bytes `C0 27 09 00`. A reader that
assumes big-endian parses those same bytes as `0xC0270900` = `−1071183616`, which the limit check
rejects — so the failure is loud rather than silent — but a hand-written reader in another language
must get this right.

Byte values in this document are written in hexadecimal (`0x10`, or `EC DE` for a byte sequence).

### 1.2 Offsets

All offsets are **absolute, zero-based, from the first byte of the container**. `N` denotes a
variable-length field's byte count, itself carried in the header.

---

## 2. Common prefix — all methods

The first five bytes are identical in shape across every method.

| Offset | Size | Field | Values |
|---|---|---|---|
| 0 | 2 | Magic | `EC DE` |
| 2 | 1 | Method | `0x01` PBKDF2 · `0x02` Argon2 · `0x03` RSA · `0x04` ML-KEM · `0x05` **reserved** |
| 3 | 1 | Format version | `0x10` = this format · `0x01`–`0x0F` **reserved** |
| 4 | 1 | Cipher | `0x01` AES-256-GCM · `0x02` Twofish-256-GCM · `0x03` Serpent-256-GCM · `0x04` Camellia-256-GCM |

### 2.1 Magic

The two bytes `EC DE`, in that order — byte 0 is `0xEC`, byte 1 is `0xDE`. A container whose first
two bytes are anything else is not an Enigma.DataEncryption container.

### 2.2 Method

Identifies which key-establishment method produced the container, and therefore how the rest of the
header is laid out.

| Byte | Method | Credential |
|---|---|---|
| `0x01` | PBKDF2 | password |
| `0x02` | Argon2 | password |
| `0x03` | RSA | RSA key pair (PEM) |
| `0x04` | ML-KEM | ML-KEM key pair (raw FIPS 203 bytes) |
| `0x05` | **Reserved** — true RSA + ML-KEM hybrid | *(not implemented)* |

`0x05` is reserved, not implemented. Reserving it now costs nothing and avoids a format-version bump
when the hybrid method lands. A reader of this format version **must reject** `0x05`.

Each service reads only its own method byte. Handing a PBKDF2 container to the RSA service is a
format error, not a silent misparse.

### 2.3 Format version

`0x10` is this format. Values `0x01`–`0x0F` are **reserved for legacy
`Enigma.Cryptography.DataEncryption` containers** — the predecessor library used that range, and
reserving it keeps a future legacy-reader from having to disambiguate. A reader of this format
version **must reject** every value other than `0x10`.

### 2.4 Cipher

The 256-bit AEAD block cipher used for the payload. All four run in **GCM** mode with a 128-bit
authentication tag.

| Byte | Cipher | Enigma.Core factory method |
|---|---|---|
| `0x01` | AES-256-GCM | `IBlockCipherServiceFactory.CreateAesService` |
| `0x02` | Twofish-256-GCM | `IBlockCipherServiceFactory.CreateTwofishService` |
| `0x03` | Serpent-256-GCM | `IBlockCipherServiceFactory.CreateSerpentService` |
| `0x04` | Camellia-256-GCM | `IBlockCipherServiceFactory.CreateCamelliaService` |

The cipher is header-selectable because all four choices are equally sound at 256 bits; it is the
only algorithmic degree of freedom the format offers (see §4).

---

## 3. Method bodies

### 3.1 PBKDF2 — method `0x01`

**Header length: 53 bytes.**

| Offset | Size | Field |
|---|---|---|
| 0 | 5 | Common prefix (§2), method `0x01` |
| 5 | 12 | GCM nonce |
| 17 | 16 | PBKDF2 salt |
| 33 | 4 | Iterations (`Int32` LE) |
| 37 | 16 | Key-confirmation tag (§6) |
| **53** | var | GCM payload (ciphertext ‖ 16-byte authentication tag) |

The data key is `PBKDF2-HMAC-SHA256(password, salt, iterations, 32)`.

### 3.2 Argon2 — method `0x02`

**Header length: 61 bytes.**

| Offset | Size | Field |
|---|---|---|
| 0 | 5 | Common prefix (§2), method `0x02` |
| 5 | 12 | GCM nonce |
| 17 | 16 | Argon2 salt |
| 33 | 4 | Iterations / passes (`Int32` LE) |
| 37 | 4 | Degree of parallelism (`Int32` LE) |
| 41 | 4 | **Memory size in KiB** (`Int32` LE) |
| 45 | 16 | Key-confirmation tag (§6) |
| **61** | var | GCM payload |

The data key is `Argon2id(password, salt, iterations, memorySizeKb, degreeOfParallelism, 32)` at
Argon2 version 1.3.

> **Deliberate divergence from the predecessor.** `Enigma.Cryptography.DataEncryption` stored
> `memoryPowOfTwo` and its reader allocated `2^memoryPowOfTwo` KiB. **This format stores the KiB value
> directly**, matching `Enigma.Core.KeyDerivation.IArgon2Service.DeriveKey(…, memorySizeKb, …)` — no
> exponent round-trip, and every value expressible rather than only powers of two.
>
> A reader of legacy containers therefore needs a conversion step,
> `memorySizeKb = 1 << memoryPowOfTwo`, rather than a straight field read. Note also that the field
> **order** differs: this format writes parallelism before memory.

### 3.3 RSA — method `0x03`

**Header length: 37 + N bytes**, where `N` is the wrapped-key length.

| Offset | Size | Field |
|---|---|---|
| 0 | 5 | Common prefix (§2), method `0x03` |
| 5 | 12 | GCM nonce |
| 17 | 4 | Wrapped-key length `N` (`Int32` LE) |
| 21 | `N` | Wrapped data key — **RSAES-OAEP with SHA-256** over the 32-byte data key |
| 21 + `N` | 16 | Key-confirmation tag (§6) |
| **37 + `N`** | var | GCM payload |

`N` equals the RSA modulus size in bytes (256 for RSA-2048, 512 for RSA-4096).

There is **no public-key fingerprint field**. OAEP unwrap already fails fast on the wrong key, and
the key-confirmation tag (§6) covers wrong-credential detection uniformly across all four methods, so
a fingerprint would add a correlatable identifier to the container for no detection benefit.

### 3.4 ML-KEM — method `0x04`

**Header length: 38 + N bytes**, where `N` is the encapsulation length.

| Offset | Size | Field |
|---|---|---|
| 0 | 5 | Common prefix (§2), method `0x04` |
| 5 | 1 | Parameter set — `0x01` ML-KEM-512 · `0x02` ML-KEM-768 · `0x03` ML-KEM-1024 |
| 6 | 12 | GCM nonce |
| 18 | 4 | Encapsulation (ciphertext) length `N` (`Int32` LE) |
| 22 | `N` | ML-KEM encapsulation |
| 22 + `N` | 16 | Key-confirmation tag (§6) |
| **38 + `N`** | var | GCM payload |

`N` is determined by the parameter set: 768 bytes for ML-KEM-512, 1088 for ML-KEM-768, 1568 for
ML-KEM-1024.

> **The parameter-set byte is a wire encoding, not the enum's numeric value.**
> `Enigma.Core.Asymmetric.Pqc.MLKemParameterSet` is a plain (unnumbered) C# enum whose members happen
> to be `0`, `1`, `2`. The wire bytes are `0x01`, `0x02`, `0x03` — deliberately 1-based so that `0x00`
> is never a valid value and a zero-filled header cannot parse. Implementations must map explicitly
> and must not cast.

**The 32-byte ML-KEM shared secret is used directly as the data key.** No extra KDF step is applied.
FIPS 203 shared secrets are uniformly random 32-byte values — exactly what a 256-bit data key needs —
and the context binding a KDF would normally provide is already achieved by passing the complete
header as AAD (§5). This is a decision, not an omission.

Note that FIPS 203 **implicit rejection** means decapsulation with a wrong private key *succeeds*,
returning a wrong-but-well-formed shared secret. The key-confirmation tag (§6) is what turns that
into a clean, fast error.

---

## 4. Fixed parameters

These are invariants of the format. **None of them is stored in the header, and none is
selectable.**

| Parameter | Value |
|---|---|
| Data key size | 32 bytes (256-bit) |
| GCM nonce size | 12 bytes (96-bit) |
| GCM authentication tag | 128 bits (`Enigma.Core.Symmetric.BlockCiphers.GcmMacSize.MaxBits`) |
| Salt size (PBKDF2 / Argon2) | 16 bytes |
| PBKDF2 PRF | HMAC-SHA256 (`Enigma.Core.KeyDerivation.Pbkdf2Prf.HmacSha256`) |
| Argon2 variant | Argon2id (`Enigma.Core.KeyDerivation.Argon2Variant.Argon2id`) |
| Argon2 version | 1.3 (`Enigma.Core.KeyDerivation.Argon2Version.Version13`) |
| RSA key wrapping | RSAES-OAEP, SHA-256 (`Enigma.Core.Asymmetric.PublicKey.RsaOaepHash.Sha256`) |
| Key-confirmation tag size | 16 bytes |
| Key-confirmation MAC | HMAC-SHA256, truncated to the leftmost 16 bytes |
| GCM padding | none (`Enigma.Core.Padding.PaddingScheme.None`) |

Keeping these out of the header is deliberate: **an attacker-editable algorithm selector is a
downgrade lever**, and every one of these choices is already the correct one. There is no
"negotiation" to be had, so the format offers none. (The header *is* authenticated — §5 — so an edit
would be detected; the point is that there is nothing worth offering an attacker in the first place.)

The only algorithmic field a container carries is the cipher byte (§2.4), where all four options are
equivalent 256-bit AEADs and no choice is a downgrade of another.

### 4.1 Default cost parameters

These are defaults chosen at encryption time — they *are* stored in the header, because a reader must
reproduce them.

| Parameter | Default | Source |
|---|---|---|
| PBKDF2 iterations | 600,000 | OWASP 2023 floor for PBKDF2-HMAC-SHA256 |
| Argon2 iterations | 3 | RFC 9106, second recommended option |
| Argon2 memory | 65,536 KiB (64 MiB) | RFC 9106, second recommended option |
| Argon2 degree of parallelism | 4 | RFC 9106, second recommended option |

---

## 5. Header authentication (AAD)

**The complete header — byte 0 through the final byte of the key-confirmation tag — is passed as
`associatedData` to `IBlockCipherService.EncryptAsync` / `DecryptAsync`.**

The GCM authentication tag therefore covers the header as well as the payload. **Any edit to any
header byte is an authentication failure.** Flipping the cipher byte, lowering the iteration count,
swapping a salt or truncating the wrapped key all produce the same outcome: decryption fails.

The AAD is exactly the header, and exactly once: the header bytes are not also prefixed to the
plaintext, and the payload contains no copy of them.

**There is no circularity** between §5 and §6, and the ordering is what makes that so:

1. The key-confirmation tag is computed over the header bytes **preceding** it.
2. The AAD is the header **including** that tag.

So the tag is fully determined before the AAD exists, and the AAD is fully determined before the GCM
operation begins.

---

## 6. Key confirmation

Every header ends with a 16-byte key-confirmation tag, computed from the data key `K`:

```
kcKey = HMAC-SHA256(K, ASCII("Enigma.DataEncryption/kc/v1"))
kcTag = HMAC-SHA256(kcKey, headerBytesBeforeTag)[0..16]
```

where:

- `ASCII("Enigma.DataEncryption/kc/v1")` is the 27-byte US-ASCII encoding of that label, with no
  trailing NUL. In hex:
  `45 6E 69 67 6D 61 2E 44 61 74 61 45 6E 63 72 79 70 74 69 6F 6E 2F 6B 63 2F 76 31`
- `K` is the 32-byte data key, used here as the **HMAC key** (not as the message).
- `headerBytesBeforeTag` is every header byte from offset 0 up to, but not including, the tag —
  i.e. the first 37 bytes for PBKDF2, 45 for Argon2, 21 + `N` for RSA, 22 + `N` for ML-KEM.
- `[0..16]` is the **leftmost** 16 bytes of the 32-byte HMAC output.

### 6.1 Why a separate confirmation key

`kcKey` is derived rather than MAC-ing with `K` directly so that **no tag computed under the data key
itself is ever published**. The container exposes `kcTag`, which is a MAC under `kcKey`; `K` is used
only as the HMAC key of the one-shot derivation, whose output never leaves the process.

### 6.2 Verification

The tag is verified with a **constant-time** comparison, **as soon as `K` is available and before a
single payload byte is read**. A mismatch is a decryption error (wrong credential), reported without
touching the payload.

### 6.3 Consequences

**Uniform fast-fail across all four methods.** A wrong password, a wrong RSA key or a wrong ML-KEM key
all produce the same clean error at the same point, in time proportional to the header rather than the
file. For ML-KEM this is the *only* early detection available, because FIPS 203 implicit rejection
makes decapsulation with a wrong key succeed (§3.4). Without it, a wrong ML-KEM key would surface as a
GCM authentication failure only after streaming the entire payload.

**The construction is key-committing.** Plain GCM is not: it is possible to construct a single
ciphertext that authenticates correctly under two different keys, decrypting to two different
plaintexts. Binding `kcTag` to the header — and the header, via AAD, to the payload — commits the
container to one key.

**Security note — header-only guessing.** An offline attacker holding the container can test a
password guess against the header alone: derive `K`, compute `kcTag`, compare. They do not need the
payload. **This is not a weakening.** The header travels inside the same file as the payload, so an
attacker who has one has both; withholding the tag would buy nothing but a constant factor. The actual
defence against guessing is, as always, the KDF work factor per guess (§4.1) — 600,000 PBKDF2
iterations or 64 MiB of Argon2id memory per attempt.

---

## 7. Canonical operation order

### 7.1 Encrypt

1. **Validate arguments** — streams non-null, credential non-null/non-empty, cipher defined, cost
   parameters in range.
2. **Generate** the salt (16 bytes), the GCM nonce (12 bytes) and — for RSA and ML-KEM — the data key
   (32 bytes), from `IRandomSource`.
3. **Derive or obtain `K`**: PBKDF2/Argon2 derive it from the password and salt; RSA wraps a freshly
   generated `K` under the recipient's public key; ML-KEM encapsulates against the recipient's public
   key and takes the shared secret as `K`.
4. **Build the header in memory** — every field except the key-confirmation tag.
5. **Compute `kcTag`** over those bytes (§6) and **append** it. The header is now complete.
6. **Write the full header** to the output stream.
7. **Encrypt the payload**:
   `EncryptAsync(input, output, K, nonce, BlockCipherMode.Gcm, PaddingScheme.None, 128, associatedData: fullHeader, progress, cancellationToken)`.
8. **Clear `K` and `kcKey`** in a `finally`.

### 7.2 Decrypt

1. **Read and validate the common prefix** — magic is `EC DE`; the method byte matches the service
   being used; the version byte is `0x10`; the cipher byte is defined.
2. **Read the method-body fields**, including the parameter-set byte for ML-KEM.
3. **Validate every cost and length field against `DataEncryptionLimits` (§8) — before any allocation
   or KDF work.** This ordering is the point of the limits: a header claiming 2,000,000,000 Argon2
   iterations must be rejected by arithmetic, not survived by computation.
4. **Derive or unwrap `K`**: PBKDF2/Argon2 re-derive from the password and the stored salt and costs;
   RSA unwraps the wrapped key; ML-KEM decapsulates the encapsulation.
5. **Recompute and verify `kcTag`** with a constant-time comparison (§6.2). On mismatch, fail here —
   no payload byte has been read.
6. **Decrypt the payload** with the same AAD (the complete header as read):
   `DecryptAsync(input, output, K, nonce, BlockCipherMode.Gcm, PaddingScheme.None, 128, associatedData: fullHeader, progress, cancellationToken)`.
7. **Clear `K` and `kcKey`** in a `finally`.

Decryption **does not require a seekable input stream**: the header is read forward, once, and the
payload is streamed from wherever the header ended.

---

## 8. Limits

Every variable cost and length field is bounded. The caps are configurable through
`DataEncryptionLimits`; the defaults are:

| Field | Default cap |
|---|---|
| PBKDF2 iterations | 10,000,000 |
| Argon2 iterations | 64 |
| Argon2 memory (KiB) | 1,048,576 (1 GiB) |
| Argon2 degree of parallelism | 64 |
| RSA wrapped-key length | 4,096 bytes |
| ML-KEM encapsulation length | 4,096 bytes (the true maximum is 1,568) |

A field that is `<= 0`, or that exceeds its cap, is a **format error**.

**The check happens before any allocation or key-derivation work.** These caps exist so that a
hostile header cannot turn a decrypt attempt into a denial of service — allocating gigabytes or
spinning for hours on cost parameters the attacker chose. Reading a bounded integer and comparing it
is cheap; acting on it first is not.

The caps are generous relative to legitimate use (see §4.1) and are not a statement about what
parameters are *sensible* — only about what is *survivable*.

---

## 9. Error mapping

The exception a reader raises is part of the contract.

| Condition | Exception |
|---|---|
| Magic is not `EC DE` | `DataEncryptionFormatException` |
| Method byte undefined, or does not match the service being used | `DataEncryptionFormatException` |
| Version byte not `0x10` (includes every reserved legacy value) | `DataEncryptionFormatException` |
| Cipher byte undefined | `DataEncryptionFormatException` |
| ML-KEM parameter-set byte undefined | `DataEncryptionFormatException` |
| Stream ends inside the header | `DataEncryptionFormatException` |
| A cost or length field exceeds `DataEncryptionLimits`, or is `<= 0` | `DataEncryptionFormatException` |
| `Enigma.Core` `ReadLengthValue*` `InvalidOperationException` | translated to `DataEncryptionFormatException` |
| RSA wrapped key that unwraps to a length other than 32 bytes | `DataEncryptionFormatException` |
| Key-confirmation tag mismatch | `DataDecryptionException` |
| GCM authentication failure (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| RSA OAEP unwrap failure, **including an undecryptable private-key PEM** (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| Malformed / unparseable private-key PEM | propagates from Enigma.Core (`ArgumentException` / `FormatException`) — **not** wrapped, since it is a credential-supply error, not a file-content error |
| ML-KEM decapsulation failure, **including a private key that is malformed or for another parameter set** (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| ML-KEM encapsulation failure — the caller's public key is malformed or for another parameter set (`CryptographicException`) | `ArgumentException` on `publicKey`, wrapping it |
| Null / empty / out-of-range arguments | `ArgumentNullException` / `ArgumentException` / `ArgumentOutOfRangeException` |
| Cancellation | `OperationCanceledException` |

> **Why an undecryptable private-key PEM is not separated out.** Enigma.Core reports a wrong RSA private
> key, an encrypted PEM opened with the wrong passphrase, and an encrypted PEM opened with no passphrase
> as the *same* `CryptographicException` from the *same* `DecryptOaep` call, and their BouncyCastle inner
> exception types overlap — nothing but the message text distinguishes them. Rather than match on message
> text, all three are reported as `DataDecryptionException` with the original exception kept as
> `InnerException`, where the specific cause stays readable. A PEM that cannot be *parsed* does keep its
> own identity, because `ArgumentException` and `FormatException` are unambiguous. The credential-supply
> versus file-content split therefore holds wherever the underlying library lets it be observed.

> **Why ML-KEM is asymmetric between the two directions.** Enigma.Core's `Decapsulate` raises a single
> `CryptographicException` whose own message names three causes at once — a malformed ciphertext, a
> malformed private key, or either being for a different parameter set. Two of those point in opposite
> directions: a wrong-length key is the *caller's* problem, an edited parameter-set byte is the
> *container's*. Since they are indistinguishable without matching on message text, both are reported as
> `DataDecryptionException`, because announcing an argument error for a tampered file would be the worse
> of the two mistakes. `Encapsulate` has no such ambiguity — it takes the public key and nothing else, so
> a failure can only be about the key the caller supplied, and it is reported as `ArgumentException` on
> `publicKey`. Enigma.Core's RSA path already reports an unusable public key that way, so the two methods
> agree on the encrypt side.

`DataEncryptionFormatException` and `DataDecryptionException` both derive from
`DataEncryptionException`, so a caller that does not care which can catch the base type.

The split is meaningful: **format** means *this is not a container I can parse*, **decryption** means
*this is a valid container and I could not open it* — in practice, the wrong credential.

**A header-only reader raises the format half alone.** Reading a header uses no credential and consumes
no payload byte, so every row above that yields `DataDecryptionException` is unreachable for it: an
inspector rejects a malformed container and reports an edited-but-valid cipher or parameter-set byte as
it found it, because detecting *that* edit is the AAD's job (§5) and requires a key it does not have.

---

## 10. Reserved values — summary

| Where | Value(s) | Reserved for |
|---|---|---|
| Method byte (offset 2) | `0x05` | True RSA + ML-KEM hybrid |
| Format version (offset 3) | `0x01`–`0x0F` | Legacy `Enigma.Cryptography.DataEncryption` containers |

A conforming reader of format version `0x10` rejects both ranges. They are recorded here so that a
later implementation does not need a format-version bump to claim them.
