# FEATURE-5A30 — True hybrid RSA + ML-KEM method `0x05` (deferred)

**Status:** TODO — **deliberately deferred; not part of the v1.0.0 release**
**Type:** FEATURE (single-phase)
**Suggested branch:** `feature/feature-5a30-hybrid`
**Depends on:** FEATURE-11B6 (complete)

## Why this exists as a planned item

Neither the RSA nor the ML-KEM method in v1.0.0 is "hybrid" in the post-quantum sense. Each wraps the
data key under **one** primitive, so each file is only as strong as that primitive:

- an RSA file is broken by a sufficiently large quantum computer;
- an ML-KEM file is broken if a classical cryptanalytic break of ML-KEM is found.

A **true hybrid** wraps the data key under both, combining the two secrets so the file stays secure as
long as **either** primitive holds. That is what NIST and IETF post-quantum migration guidance actually
recommend for the transition period, and it is the strongest option this library could offer.

It is deferred to keep v1.0.0's scope exactly where it was set. Method byte **`0x05` is reserved for it
in `docs/format.md`** from FEATURE-00E7 onward, so adding it later needs no format-version bump and no
awkward byte allocation.

## Objective

Add a fifth encryption method that wraps the data key under an RSA public key **and** an ML-KEM public
key, deriving the data key from both secrets, so that breaking one primitive is insufficient.

## Design sketch (to be settled during the dev, not assumed here)

**This is the one item in the roadmap whose core construction deserves careful review before
implementation.** A key combiner is easy to get subtly wrong, and an incorrect one can be *weaker* than
either input. Settle the construction first, write it into `docs/format.md`, then implement.

Starting point for that discussion:

- Generate a random 32-byte value, wrap it with RSA-OAEP-SHA256 → `wrappedRsaSecret`.
- Encapsulate against the ML-KEM public key → `(encapsulation, kemSecret)`.
- Combine into the data key with a KDF-style combiner over **both** secrets **and** the two ciphertexts,
  so the combined key is bound to the exact wrapping material. A standard shape is
  `K = HMAC-SHA256(salt: fixedLabel, ikm: rsaSecret ‖ kemSecret ‖ wrappedRsaSecret ‖ encapsulation)`,
  i.e. an HKDF-Extract-then-Expand built from Enigma.Core's `IHmacService`. Enigma.Core has no HKDF, so
  the combiner must be built from HMAC-SHA256 primitives — which is exactly why it needs review rather
  than improvisation.
- Requirement to hold: the construction must be **secure if either** input secret is secure. A plain
  XOR or concatenation-without-KDF does not reliably give that property.

**Format**, following the existing conventions (authenticated header as AAD, key-confirmation tag,
little-endian `Int32`, length-value for variable fields):

```
0    2   magic EC DE
2    1   method 05
3    1   version 10
4    1   cipher
5    1   ML-KEM parameter set
6   12   nonce
18   4   wrapped-RSA-secret length  (Int32 LE)
22   N   wrapped RSA secret        (OAEP-SHA256)
..   4   encapsulation length      (Int32 LE)
..   M   ML-KEM encapsulation
..  16   key-confirmation tag
..  var  GCM payload
```

**API**, consistent with the existing four services:

```csharp
public interface IHybridDataEncryptionService
{
    Task EncryptAsync(Stream input, Stream output, Cipher cipher,
        string rsaPublicKeyPem, byte[] mlKemPublicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    Task DecryptAsync(Stream input, Stream output,
        string rsaPrivateKeyPem, byte[] mlKemPrivateKey, char[]? rsaKeyPassword = null,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);
}
```

Both credentials are required in both directions — that is the point of the method, and the XML docs
must say so plainly.

Also required: add `Hybrid = 0x05` to `EncryptionMethod`; extend `EncryptedDataHeader` with the second
length property; extend `IEncryptedDataInspector`; extend `DataEncryptionLimits` if a second cap is
needed; register in `AddEnigmaDataEncryption()`; add the file-path extension pair.

## Test strategy

Everything the other three public-key phases have, plus the properties specific to hybrids:

- Round-trip × 4 ciphers × 3 ML-KEM parameter sets, with RSA-2048/3072.
- **Wrong RSA key but correct ML-KEM key → fails.** **Correct RSA key but wrong ML-KEM key → fails.**
  Both at the key-confirmation stage. These two tests are what demonstrate that both secrets genuinely
  contribute to the data key — without them, a broken combiner that silently ignores one input would
  pass every other test in the suite.
- A byte-exact golden vector for the deterministic header portion, plus committed fixture files for the
  read path.
- Tamper coverage over both variable-length fields.
- The full malformed-input sweep extended to the `0x05` shape.

## Acceptance criteria

1. The key-combiner construction is written into `docs/format.md` **before** implementation, with its
   security rationale stated.
2. Both "one credential wrong" tests pass, proving both inputs contribute.
3. Method `0x05` round-trips across all cipher and parameter-set combinations.
4. Header authenticated as AAD and key-confirmation tag present, consistent with the other four methods.
5. Inspector, DI registration, file-path extensions and `docs/guides/` all extended.
6. `RELEASENOTES.md` records it as a new feature, and the README *Features* list is updated.
7. `BouncyCastleIsolationTests` still passes.
8. Zero-warning Release build; full suite green on both test TFMs.

## If this is dropped

Mark the row `ABANDONED` with a reason. Reserved method byte `0x05` should then stay reserved in
`docs/format.md` rather than being reused, so the reservation continues to document the decision.
