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
| 2 | 1 | Method | `0x01` PBKDF2 · `0x02` Argon2 · `0x03` RSA · `0x04` ML-KEM · `0x05` hybrid RSA + ML-KEM |
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
| `0x05` | Hybrid RSA + ML-KEM | **both** — an RSA key pair (PEM) *and* an ML-KEM key pair (raw FIPS 203 bytes) |

`0x05` was reserved by earlier revisions of this document and is now assigned (§3.5). Reserving it in
advance is what let the hybrid method land without a format-version bump. Values `0x06`–`0xFF` are
unassigned; a reader of this format version **must reject** them.

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

The cipher is header-selectable because all four choices are equally sound at 256 bits. It is one of
only **two** algorithmic degrees of freedom the format offers — the other being method `0x03`'s
RSA-OAEP hash (§3.3) — and both are selectable for the same reason: within each field, no accepted
value is a downgrade of another (see §4).

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

**Header length: 38 + N bytes**, where `N` is the wrapped-key length.

| Offset | Size | Field |
|---|---|---|
| 0 | 5 | Common prefix (§2), method `0x03` |
| 5 | 1 | OAEP hash — `0x02` SHA-256 · `0x03` SHA-384 · `0x04` SHA-512 |
| 6 | 12 | GCM nonce |
| 18 | 4 | Wrapped-key length `N` (`Int32` LE) |
| 22 | `N` | Wrapped data key — **RSAES-OAEP with the selected hash** over the 32-byte data key |
| 22 + `N` | 16 | Key-confirmation tag (§6) |
| **38 + `N`** | var | GCM payload |

`N` equals the RSA modulus size in bytes (256 for RSA-2048, 512 for RSA-4096), independently of the
hash.

The OAEP-hash byte occupies the same offset 5 that §3.4 and §3.5 give their parameter-set byte, so all
three public-key methods carry their algorithm selector in the same place, and methods `0x03` and `0x04`
are structurally identical: both are `38 + N`.

> **The hash byte is a wire encoding, not the enum's numeric value.**
> `Enigma.Core.Asymmetric.PublicKey.RsaOaepHash` is a plain (unnumbered) C# enum declaring
> `Sha1`, `Sha256`, `Sha384`, `Sha512`. The wire bytes are 1-based and follow that declaration order —
> `0x01` SHA-1, `0x02` SHA-256, `0x03` SHA-384, `0x04` SHA-512 — so `0x00` is never a valid value and a
> zero-filled header cannot parse, exactly as in §3.4. Implementations must map explicitly and must not
> cast.

**`0x01` (SHA-1) is reserved, not accepted** (§10). A writer must never emit it and a reader must reject
it. Numbering it anyway is what keeps enabling SHA-1 later a pure un-reservation rather than a
renumbering. Nothing mandates OAEP-SHA-1, and because no external system ever unwraps these keys, the
legacy-interop argument that usually rescues SHA-1 does not apply here.

**SHA-256 is the default.** SHA-384 and SHA-512 exist for callers under a policy that mandates them for
key transport; they are not stronger choices here (see §4). The hash does interact with the key size:
RFC 8017 §7.1.1 requires `k >= 2·hLen + 34` to wrap a 32-byte data key, so an RSA-1024 modulus (128
bytes) is too small for SHA-384 (needs 130) and SHA-512 (needs 162). RSA-2048 and above accept all
three.

**A reader takes the hash from the header, never from its caller.** Decryption has no hash parameter;
the byte at offset 5 selects the unwrap. An edited byte therefore makes the OAEP unwrap fail, which §9
already covers — it needs no rule of its own.

There is **no public-key fingerprint field**. OAEP unwrap already fails fast on the wrong key, and
the key-confirmation tag (§6) covers wrong-credential detection uniformly across every method, so
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

### 3.5 Hybrid RSA + ML-KEM — method `0x05`

**Header length: 42 + `N` + `M` bytes**, where `N` is the wrapped-secret length and `M` the
encapsulation length.

| Offset | Size | Field |
|---|---|---|
| 0 | 5 | Common prefix (§2), method `0x05` |
| 5 | 1 | Parameter set — `0x01` ML-KEM-512 · `0x02` ML-KEM-768 · `0x03` ML-KEM-1024 |
| 6 | 12 | GCM nonce |
| 18 | 4 | Wrapped-secret length `N` (`Int32` LE) |
| 22 | `N` | Wrapped RSA secret — **RSAES-OAEP with SHA-256** over a 32-byte random secret |
| 22 + `N` | 4 | Encapsulation (ciphertext) length `M` (`Int32` LE) |
| 26 + `N` | `M` | ML-KEM encapsulation |
| 26 + `N` + `M` | 16 | Key-confirmation tag (§6) |
| **42 + `N` + `M`** | var | GCM payload |

`N` equals the RSA modulus size in bytes; `M` is fixed by the parameter set, exactly as in §3.4. The
parameter-set byte is the same wire encoding as §3.4 — 1-based, mapped explicitly, never cast — and it
occupies the same offset 5, so a hybrid header and an ML-KEM header agree on their first 18 bytes but
for the method byte.

**Neither field is optional and neither credential is.** A hybrid container is opened by the RSA private
key *and* the ML-KEM private key together; holding one of the two is worth nothing. That is the entire
point of the method.

#### 3.5.1 The key combiner

This method is the only one whose data key is neither derived from a credential nor transported whole.
It is **combined** from two independently transported secrets:

- `rsaSecret` — a 32-byte value drawn from the RNG and wrapped under the recipient's RSA public key with
  RSAES-OAEP-SHA-256, producing `wrappedRsaSecret` (`N` bytes);
- `kemSecret` — the 32-byte FIPS 203 shared secret produced by encapsulating against the recipient's
  ML-KEM public key, alongside `encapsulation` (`M` bytes).

The data key `K` is:

```
T    = LE32(N) ‖ wrappedRsaSecret ‖ LE32(M) ‖ encapsulation

Krsa = HMAC-SHA256(key: rsaSecret, message: ASCII("Enigma.DataEncryption/hybrid/rsa/v1")   ‖ T)
Kkem = HMAC-SHA256(key: kemSecret, message: ASCII("Enigma.DataEncryption/hybrid/mlkem/v1") ‖ T)

K    = Krsa XOR Kkem
```

where:

- `LE32(x)` is the signed 32-bit little-endian encoding of §1.1 — so **`T` is exactly the contiguous
  header slice from offset 18 up to, but not including, the key-confirmation tag** (bytes 18 through
  26 + `N` + `M`). It is defined as a header slice on purpose: an implementation can produce it by
  copying, and a reviewer can locate it in a hex dump.
- the two labels are US-ASCII, with no trailing NUL. In hex:
  - `Enigma.DataEncryption/hybrid/rsa/v1` (35 bytes) —
    `45 6E 69 67 6D 61 2E 44 61 74 61 45 6E 63 72 79 70 74 69 6F 6E 2F 68 79 62 72 69 64 2F 72 73 61 2F 76 31`
  - `Enigma.DataEncryption/hybrid/mlkem/v1` (37 bytes) —
    `45 6E 69 67 6D 61 2E 44 61 74 61 45 6E 63 72 79 70 74 69 6F 6E 2F 68 79 62 72 69 64 2F 6D 6C 6B 65 6D 2F 76 31`
- each secret is the **HMAC key** of its own invocation, never part of a message.
- `XOR` is bytewise over all 32 bytes. HMAC-SHA256 outputs 32 bytes, which is exactly the data-key
  size, so there is no truncation and no expansion step.

`K` is then used exactly as every other method's data key: it seals the key-confirmation tag (§6) and
it is the GCM key for the payload (§5).

#### 3.5.2 Why this combiner

The requirement is one sentence: **the container must stay secure as long as *either* primitive holds.**
An RSA-only container falls to a sufficiently large quantum computer; an ML-KEM-only container falls to a
classical break of ML-KEM. A hybrid that is only as strong as its weaker half would be pointless, and a
careless combiner is exactly that.

**The construction above is a *split-key PRF*: a PRF that is secure if either of its two keys is.** The
argument is one line in each direction. Suppose `rsaSecret` is a uniformly random 32-byte value the
adversary does not know. Then `Krsa` is indistinguishable from a uniform 32-byte string, and
`Krsa XOR Kkem` is too — XOR-ing an adversary-known value into an indistinguishable-from-random value
leaves it indistinguishable from random. The same argument holds with the roles swapped. So `K` is a good
key unless **both** secrets are recovered, which is the property asked for. This is the split-key-PRF
combiner of Giacon–Heuer–Poettering's *KEM Combiners*, instantiated with HMAC-SHA256.

Three details are load-bearing rather than decorative:

- **Neither secret is concatenated into a message.** `HMAC-SHA256(salt, s1 ‖ s2)` — the HKDF-Extract
  shape — would also be defensible, and it is what TLS 1.3's hybrid key schedule does. It was **not**
  chosen, because its "secure if either holds" argument needs HMAC to be a PRF when keyed by part of its
  *message* (the dual-PRF property) rather than by its key. That is a stronger assumption than anything
  else in this format relies on. Keying each HMAC with its own secret needs only that HMAC-SHA256 is a
  PRF — the same assumption §6 already makes.
- **The two labels differ.** They are what stops the degenerate case `rsaSecret == kemSecret`, in which
  a single shared label would give `Krsa == Kkem` and therefore `K == 0`. That case is not merely a
  2⁻²⁵⁶ accident: a hostile *sender* can force it, because it encapsulates first, sees `kemSecret`, and
  then chooses which value to wrap under RSA. With distinct labels the two messages differ, so the two
  HMAC outputs do not cancel. A container whose data key was all zeros would be readable by anyone
  holding neither private key.
- **Both ciphertexts are inside `T`.** `K` is therefore bound to the exact wrapping material that
  produced it, so neither ciphertext can be swapped, reordered or spliced in from another container
  without changing `K`. Without that binding, a combiner over the two secrets alone would be malleable
  in precisely the way KEM-combiner analyses warn about.

**What is *not* claimed.** Plain XOR of the two *secrets*, or their concatenation used directly as a key,
would not give the property above; neither is what this is. The XOR here is of two PRF outputs, each
keyed by one secret, over a common transcript — a different construction with a different argument.

**Authentication is not part of the claim either.** As with §3.3 and §3.4, anyone holding the two public
keys can produce a valid container, so a successful decrypt proves the container was made *for* the
recipient, not *by* anyone in particular.

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
| RSA key wrapping (**method `0x05` only**) | RSAES-OAEP, SHA-256 (`Enigma.Core.Asymmetric.PublicKey.RsaOaepHash.Sha256`) — method `0x03`'s wrapping hash is a header field instead, see §3.3 |
| Hybrid key combiner (method `0x05`) | XOR of two HMAC-SHA256 split-key PRFs (§3.5.1) |
| Hybrid combiner labels | `Enigma.DataEncryption/hybrid/rsa/v1` and `Enigma.DataEncryption/hybrid/mlkem/v1` |
| Key-confirmation tag size | 16 bytes |
| Key-confirmation MAC | HMAC-SHA256, truncated to the leftmost 16 bytes |
| GCM padding | none (`Enigma.Core.Padding.PaddingScheme.None`) |

Keeping these out of the header is deliberate: **an attacker-editable algorithm selector is a
downgrade lever**, and every one of these choices is already the correct one. There is no
"negotiation" to be had, so the format offers none. (The header *is* authenticated — §5 — so an edit
would be detected; the point is that there is nothing worth offering an attacker in the first place.)

A container carries exactly **two** algorithmic fields, and each is admitted on the same narrow ground:
within it, no accepted value is a downgrade of another.

- The **cipher byte** (§2.4) — all four options are equivalent 256-bit AEADs.
- Method `0x03`'s **OAEP-hash byte** (§3.3) — OAEP's security proof asks no collision resistance of its
  hash, so SHA-256, SHA-384 and SHA-512 are equivalent choices rather than a ladder, and the one value
  that *would* be a downgrade, SHA-1, is not accepted at all (§10). The field therefore offers nothing to
  downgrade *to*, which is why it does not reintroduce the negotiation lever this section rules out. The
  reason it is selectable is compliance, not security: a caller under a policy mandating SHA-384 or
  SHA-512 for key transport has no other way to comply.

Method `0x05` keeps a fixed OAEP-SHA-256 wrap. Its data key is a *combination* of two secrets (§3.5.1),
so the wrap is one input to a construction rather than the whole of key transport, and it carries no
compliance argument of its own — the table row above is normative for it.

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
  i.e. the first 37 bytes for PBKDF2, 45 for Argon2, 22 + `N` for RSA, 22 + `N` for ML-KEM, and
  26 + `N` + `M` for the hybrid.
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

**Uniform fast-fail across all five methods.** A wrong password, a wrong RSA key, a wrong ML-KEM key or
either half of a wrong hybrid credential pair all produce the same clean error at the same point, in time
proportional to the header rather than the file. For ML-KEM this is the *only* early detection available,
because FIPS 203 implicit rejection makes decapsulation with a wrong key succeed (§3.4). Without it, a
wrong ML-KEM key would surface as a GCM authentication failure only after streaming the entire payload.

For the hybrid method (§3.5) the tag does more than fail fast: it is what detects a **wrong secret** as
opposed to a wrong ciphertext. A wrong RSA private key is caught earlier, by OAEP; a wrong ML-KEM private
key is not caught at all before the tag, and neither is a sender who wraps one value under RSA while
combining another. In every one of those cases the two ciphertexts are well-formed and the header parses,
so the tag over the combined key `K` is the only check that can disagree.

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
2. **Generate** the salt (16 bytes), the GCM nonce (12 bytes) and — for RSA and the hybrid — the 32-byte
   secret the RSA wrap transports, from `IRandomSource`. ML-KEM generates no key material of its own.
3. **Derive, obtain or combine `K`**: PBKDF2/Argon2 derive it from the password and salt; RSA wraps a
   freshly generated `K` under the recipient's public key **with the OAEP hash the caller selected**
   (§3.3), which is recorded in the header; ML-KEM encapsulates against the recipient's
   public key and takes the shared secret as `K`; the hybrid does **both** — wrap, then encapsulate, then
   combine the two secrets and the two ciphertexts into `K` per §3.5.1. Both public-key operations
   precede any write, so a public key the library cannot use leaves the output stream untouched.
4. **Build the header in memory** — every field except the key-confirmation tag.
5. **Compute `kcTag`** over those bytes (§6) and **append** it. The header is now complete.
6. **Write the full header** to the output stream.
7. **Encrypt the payload**:
   `EncryptAsync(input, output, K, nonce, BlockCipherMode.Gcm, PaddingScheme.None, 128, associatedData: fullHeader, progress, cancellationToken)`.
8. **Clear `K` and `kcKey`** in a `finally` — and, for the hybrid, the two input secrets alongside them.

### 7.2 Decrypt

1. **Read and validate the common prefix** — magic is `EC DE`; the method byte matches the service
   being used; the version byte is `0x10`; the cipher byte is defined.
2. **Read the method-body fields**, including the OAEP-hash byte for RSA and the parameter-set byte for
   ML-KEM and the hybrid.
3. **Validate every cost and length field against `DataEncryptionLimits` (§8) — before any allocation
   or KDF work.** This ordering is the point of the limits: a header claiming 2,000,000,000 Argon2
   iterations must be rejected by arithmetic, not survived by computation.
4. **Derive, unwrap or combine `K`**: PBKDF2/Argon2 re-derive from the password and the stored salt and
   costs; RSA unwraps the wrapped key **under the OAEP hash the header names** — never one the caller
   supplies; ML-KEM decapsulates the encapsulation; the hybrid unwraps **and**
   decapsulates, then combines per §3.5.1. The hybrid unwraps before it decapsulates, which is why a
   wrong RSA private key is reported by OAEP while a wrong ML-KEM private key reaches step 5.
5. **Recompute and verify `kcTag`** with a constant-time comparison (§6.2). On mismatch, fail here —
   no payload byte has been read.
6. **Decrypt the payload** with the same AAD (the complete header as read):
   `DecryptAsync(input, output, K, nonce, BlockCipherMode.Gcm, PaddingScheme.None, 128, associatedData: fullHeader, progress, cancellationToken)`.
7. **Clear `K` and `kcKey`** in a `finally` — and, for the hybrid, the two recovered secrets alongside
   them. A wrong ML-KEM key still *produces* a secret (implicit rejection), and a wrong secret is still
   key material.

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

**The hybrid method (§3.5) introduces no cap of its own.** Its two variable-length fields are an RSA
wrapped secret and an ML-KEM encapsulation — the same two quantities methods `0x03` and `0x04` already
bound — so the same two caps apply to them, and both are checked before either buffer is allocated.
Adding a third and fourth cap naming the same quantities would let a reader be configured to accept a
2 KiB wrapped key from a hybrid container while refusing it from an RSA one, which is not a distinction
worth being able to express.

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
| ML-KEM parameter-set byte undefined (methods `0x04` and `0x05`) | `DataEncryptionFormatException` |
| RSA OAEP-hash byte `0x00`, the reserved `0x01`, or `0x05`–`0xFF` (method `0x03`) | `DataEncryptionFormatException` |
| Stream ends inside the header | `DataEncryptionFormatException` |
| A cost or length field exceeds `DataEncryptionLimits`, or is `<= 0` | `DataEncryptionFormatException` |
| `Enigma.Core` `ReadLengthValue*` `InvalidOperationException` | translated to `DataEncryptionFormatException` |
| RSA wrapped key that unwraps to a length other than 32 bytes | `DataEncryptionFormatException` |
| Key-confirmation tag mismatch | `DataDecryptionException` |
| GCM authentication failure (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| RSA OAEP unwrap failure, **including an undecryptable private-key PEM** (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| Malformed / unparseable private-key PEM | propagates from Enigma.Core (`ArgumentException` / `FormatException`) — **not** wrapped, since it is a credential-supply error, not a file-content error |
| Malformed / unusable **public**-key PEM | propagates from Enigma.Core (`ArgumentException` / `FormatException`) — same reasoning, on the way out |
| ML-KEM decapsulation failure, **including a private key that is malformed or for another parameter set** (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| ML-KEM encapsulation failure — the caller's public key is malformed or for another parameter set (`CryptographicException`) | `ArgumentException` on the ML-KEM public-key parameter, wrapping it |
| RSA OAEP **wrap** failure — the caller's public key is too small for the selected hash (`CryptographicException`) | `ArgumentException` on the RSA public-key parameter, wrapping it |
| An `RsaOaepHash` argument that is `Sha1` or undefined | `ArgumentOutOfRangeException` on the hash parameter |
| Null / empty / out-of-range arguments | `ArgumentNullException` / `ArgumentException` / `ArgumentOutOfRangeException` |
| Cancellation | `OperationCanceledException` |

**The hybrid method (§3.5) adds no row.** It performs an RSA unwrap and an ML-KEM decapsulation, so it
inherits both methods' rules verbatim, and they do not conflict: whichever of the two fails first reports
what that method's row says it reports. The one thing worth stating explicitly is the *order* — the RSA
unwrap runs first (§7.2 step 4), so when both credentials are wrong it is the RSA row that speaks. Note
also that only method `0x03`'s wrapped key carries the data key itself; the hybrid's carries one of two
inputs to §3.5.1 — but the 32-byte length check applies identically, and for the same reason, since a
sender chooses what it wraps.

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

> **Why an RSA wrap failure is an argument error.** A public key too small for the selected OAEP hash
> (§3.3: `k >= 2·hLen + 34`) makes Enigma.Core's `EncryptOaep` raise `CryptographicException`. This is the
> encrypt side, where the only thing the caller supplied that the operation can be about is the public key
> itself — the same situation as ML-KEM `Encapsulate` above — so it is reported the same way:
> `ArgumentException` on the public-key parameter, with the original kept as `InnerException`.
> Pre-validating the modulus size instead is not available: Enigma.Core exposes no modulus-size accessor,
> and this library parses no PEM of its own. The row covers **the default SHA-256 as well**, where it is
> reachable for any modulus below 98 bytes.

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
| Format version (offset 3) | `0x01`–`0x0F` | Legacy `Enigma.Cryptography.DataEncryption` containers |
| RSA OAEP hash (offset 5, method `0x03`) | `0x01` | OAEP-SHA-1 (§3.3) |

A conforming reader of format version `0x10` rejects both. They are recorded here so that a later
implementation does not need a format-version bump to claim them.

The OAEP-hash byte is numbered from `0x01` so that its wire values follow `RsaOaepHash`'s declaration
order, which is why SHA-1 has a value at all despite being rejected: enabling it later is then an
un-reservation and nothing more. `0x00` is not reserved — it is permanently invalid, so that a zero-filled
header cannot parse. Values `0x05`–`0xFF` are undefined and rejected, but are not reserved for anything in
particular.

Method byte `0x05` **was** reserved here, for the RSA + ML-KEM hybrid, and has since been assigned to it
(§3.5) — which is the reservation mechanism working exactly as intended: the hybrid landed without a
format-version bump. Method bytes `0x06`–`0xFF` are unassigned and are rejected, but are not reserved for
anything in particular.
