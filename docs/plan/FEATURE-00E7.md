# FEATURE-00E7 — Binary format spec & public abstraction skeleton

**Status:** TODO
**Type:** FEATURE (single-phase)
**Suggested branch:** `feature/feature-00e7-abstractions`
**Depends on:** FEATURE-67FD

## Objective

Write the **normative binary format specification** (`docs/format.md`) and the complete **public API
surface** of the library — every enum, record, exception, interface and DI registration — fully
XML-documented, with implementation bodies throwing `NotImplementedException`. Establish the
public-surface guard test from this point forward.

After this dev, the shape of the library is settled and FEATURE-11B6 fills in behaviour without
changing a single signature.

## Rationale for a separate skeleton dev

The same approach Enigma.Core used (`FEATURE-4442 — Abstraction skeleton`). Two payoffs: the format
spec and the API are reviewable as one coherent artifact before any implementation effort is spent,
and the public-surface guard test starts protecting the BouncyCastle-isolation invariant before there
is any code that could violate it.

## Part 1 — `docs/format.md` (normative)

The specification document. It is the contract the golden-vector tests in FEATURE-11B6 encode, and
the source the release guides summarise.

### Common prefix — all methods

| Offset | Size | Field | Values |
|---|---|---|---|
| 0 | 2 | Magic | `EC DE` |
| 2 | 1 | Method | `01` PBKDF2 · `02` Argon2 · `03` RSA · `04` ML-KEM · `05` **reserved** (RSA+ML-KEM hybrid, FEATURE-5A30) |
| 3 | 1 | Format version | `10` = this format. `01`–`0F` **reserved** for legacy `Enigma.Cryptography.DataEncryption` files (FEATURE-136E) |
| 4 | 1 | Cipher | `01` AES-256-GCM · `02` Twofish-256-GCM · `03` Serpent-256-GCM · `04` Camellia-256-GCM |

Integers are **`Int32` little-endian**, matching `Enigma.Core.Extensions.StreamExtensionsInt32`
(`data[0] = (byte)value; data[1] = (byte)(value >> 8); …`). The spec must state this explicitly — it
is the single most likely source of a silent interop defect.

### Method bodies

**PBKDF2 — method `0x01`, version `0x10`** (header length 53 bytes)

| Offset | Size | Field |
|---|---|---|
| 5 | 12 | GCM nonce |
| 17 | 16 | PBKDF2 salt |
| 33 | 4 | Iterations (`Int32` LE) |
| 37 | 16 | Key-confirmation tag |
| 53 | var | GCM payload (ciphertext ‖ 16-byte tag) |

**Argon2 — method `0x02`, version `0x10`** (header length 61 bytes)

| Offset | Size | Field |
|---|---|---|
| 5 | 12 | GCM nonce |
| 17 | 16 | Argon2 salt |
| 33 | 4 | Iterations / passes (`Int32` LE) |
| 37 | 4 | Degree of parallelism (`Int32` LE) |
| 41 | 4 | **Memory size in KiB** (`Int32` LE) |
| 45 | 16 | Key-confirmation tag |
| 61 | var | GCM payload |

> **Deliberate divergence from the predecessor.** The old format stored `memoryPowOfTwo` and the
> reader allocated `2^memoryPowOfTwo` KiB. This format stores the KiB value directly, matching
> `IArgon2Service.DeriveKey(..., memorySizeKb, ...)`. Document the divergence in the spec — it is the
> reason a legacy reader (FEATURE-136E) needs a conversion step (`memorySizeKb = 1 << memoryPowOfTwo`)
> rather than a straight field read.

**RSA — method `0x03`, version `0x10`** (header length 37 + N bytes)

| Offset | Size | Field |
|---|---|---|
| 5 | 12 | GCM nonce |
| 17 | 4 | Wrapped-key length N (`Int32` LE) |
| 21 | N | Wrapped data key — **RSAES-OAEP with SHA-256** over the 32-byte data key |
| 21+N | 16 | Key-confirmation tag |
| 37+N | var | GCM payload |

No public-key fingerprint field. OAEP unwrap fails fast on the wrong key, and the
key-confirmation tag covers wrong-key detection uniformly across all four methods.

**ML-KEM — method `0x04`, version `0x10`** (header length 38 + N bytes)

| Offset | Size | Field |
|---|---|---|
| 5 | 1 | Parameter set: `01` ML-KEM-512 · `02` ML-KEM-768 · `03` ML-KEM-1024 |
| 6 | 12 | GCM nonce |
| 18 | 4 | Encapsulation (ciphertext) length N (`Int32` LE) |
| 22 | N | ML-KEM encapsulation |
| 22+N | 16 | Key-confirmation tag |
| 38+N | var | GCM payload |

The 32-byte ML-KEM shared secret is used **directly** as the data key. FIPS 203 shared secrets are
uniformly random 32-byte values, and header/context binding is achieved through the AAD, so no
additional KDF step is introduced. State this reasoning in the spec so it reads as a decision rather
than an omission.

### Fixed parameters (invariants, not stored in the header)

| Parameter | Value |
|---|---|
| Data key size | 32 bytes (256-bit) |
| GCM nonce size | 12 bytes (96-bit) |
| GCM authentication tag | 128 bits (`GcmMacSize.MaxBits`) |
| Salt size (PBKDF2 / Argon2) | 16 bytes |
| PBKDF2 PRF | HMAC-SHA256 (`Pbkdf2Prf.HmacSha256`) |
| Argon2 variant | Argon2id (`Argon2Variant.Argon2id`) |
| Argon2 version | 1.3 (`Argon2Version.Version13`) |
| Key-confirmation tag size | 16 bytes |

None of these are header-selectable. That is deliberate: an attacker-editable algorithm selector is a
downgrade lever, and every one of these choices is already the correct one.

### Header authentication (AAD)

The **complete header** — byte 0 through the final byte of the key-confirmation tag — is passed as
`associatedData` to `IBlockCipherService.EncryptAsync`/`DecryptAsync`. The GCM authentication tag
therefore covers the header as well as the payload; any header edit is an authentication failure.

Note there is no circularity: the key-confirmation tag is computed over the header bytes *preceding*
it, and the AAD is the header *including* it.

### Key confirmation

```
kcKey = HMAC-SHA256(K, ASCII("Enigma.DataEncryption/kc/v1"))
kcTag = HMAC-SHA256(kcKey, headerBytesBeforeTag)[0..16]
```

- A separate confirmation key is derived rather than MAC-ing with `K` directly, so no tag computed
  under the data key itself is ever published.
- Verified with a **constant-time** comparison as soon as `K` is available and **before any payload
  byte is read**.
- Consequences to document: uniform fast-fail for all four methods (this is the only mechanism that
  detects a wrong ML-KEM private key early, since FIPS 203 implicit rejection makes decapsulation
  succeed with the wrong key), and the construction is **key-committing**, which plain GCM is not.
- Security note to include: an offline attacker can test a password guess against the header alone
  rather than needing the whole file. This is not a weakening — the header travels inside the same
  file, and the actual defence is the KDF work factor per guess.

### Canonical operation order

**Encrypt:** validate arguments → generate salt / nonce / data key via `IRandomSource` → derive or
obtain `K` → build header bytes in memory (all fields except the tag) → compute `kcTag` → append →
write the full header to the output → `EncryptAsync(input, output, K, nonce, BlockCipherMode.Gcm,
PaddingScheme.None, 128, associatedData: fullHeader, progress, ct)` → clear `K` and `kcKey` in
`finally`.

**Decrypt:** read and validate the common prefix (magic → method matches this service → version →
cipher defined) → read the method body fields → **validate every cost and length field against
`DataEncryptionLimits` before any allocation or KDF work** → derive or unwrap `K` → recompute and
verify `kcTag` → `DecryptAsync` with the same AAD → clear `K` and `kcKey` in `finally`.

### Limits

Document the default caps and the fact that they are enforced *before* allocation or KDF work:

| Field | Default cap |
|---|---|
| PBKDF2 iterations | 10,000,000 |
| Argon2 iterations | 64 |
| Argon2 memory (KiB) | 1,048,576 (1 GiB) |
| Argon2 degree of parallelism | 64 |
| RSA wrapped-key length | 4,096 bytes |
| ML-KEM encapsulation length | 4,096 bytes (true maximum is 1,568) |

## Part 2 — Public API surface

### Layout

```
src/Enigma.DataEncryption/
  Cipher.cs                              public enum Cipher : byte
  EncryptionMethod.cs                    public enum EncryptionMethod : byte
  DataEncryptionDefaults.cs              public static class
  DataEncryptionLimits.cs                public sealed class
  EncryptedDataHeader.cs                 public sealed record
  DataEncryptionFileExtensions.cs        public static class (file-path convenience)
  Exceptions/
    DataEncryptionException.cs           public abstract class
    DataEncryptionFormatException.cs     public sealed class
    DataDecryptionException.cs           public sealed class
  Services/
    IPbkdf2DataEncryptionService.cs   +  Pbkdf2DataEncryptionService.cs
    IArgon2DataEncryptionService.cs   +  Argon2DataEncryptionService.cs
    IRsaDataEncryptionService.cs      +  RsaDataEncryptionService.cs
    IMLKemDataEncryptionService.cs    +  MLKemDataEncryptionService.cs
    IEncryptedDataInspector.cs        +  EncryptedDataInspector.cs
  Internal/
    IRandomSource.cs                     internal interface
    RandomSource.cs                      internal sealed class (delegates to Enigma.Core RandomUtils)
  ServiceCollectionExtensions.cs         namespace Microsoft.Extensions.DependencyInjection
```

Public namespace: **`Enigma.DataEncryption`** for everything except the DI extension, which sits in
`Microsoft.Extensions.DependencyInjection` for discoverability (as the predecessor's Tools layer did,
with the `// ReSharper disable once CheckNamespace` comment explaining why). Internal helpers live in
`Enigma.DataEncryption.Internal`.

**Reuse, do not redefine:** `Enigma.Core.Asymmetric.Pqc.MLKemParameterSet` is the ML-KEM parameter-set
type on our public surface. Do not introduce a duplicate enum — it is already a BouncyCastle-free
public Enigma.Core type, and duplicating it would force a mapping layer for no benefit.

### Enums

```csharp
public enum Cipher : byte
{
    Aes256Gcm      = 0x01,
    Twofish256Gcm  = 0x02,
    Serpent256Gcm  = 0x03,
    Camellia256Gcm = 0x04,
}

public enum EncryptionMethod : byte
{
    Pbkdf2 = 0x01,
    Argon2 = 0x02,
    Rsa    = 0x03,
    MLKem  = 0x04,     // ReSharper disable once InconsistentNaming
}
```

Byte values are identical to the predecessor's `Cipher` / `EncryptionType`. Value `0x05` is reserved
for the hybrid method — documented in `EncryptionMethod`'s XML doc and in `docs/format.md`, but **not**
added as an enum member until FEATURE-5A30 implements it.

### Constants and limits

```csharp
public static class DataEncryptionDefaults
{
    public const byte FormatVersion              = 0x10;
    public const int  Pbkdf2Iterations           = 600_000;    // OWASP 2023 floor for PBKDF2-HMAC-SHA256
    public const int  Argon2Iterations           = 3;          // RFC 9106, second recommended option
    public const int  Argon2MemorySizeKb         = 65_536;     // 64 MiB
    public const int  Argon2DegreeOfParallelism  = 4;
    public const int  DataKeySizeBytes           = 32;
    public const int  NonceSizeBytes             = 12;
    public const int  SaltSizeBytes              = 16;
    public const int  GcmMacSizeBits             = 128;
    public const int  KeyConfirmationTagSizeBytes = 16;
}

public sealed class DataEncryptionLimits
{
    public static DataEncryptionLimits Default { get; } = new();

    public int MaxPbkdf2Iterations          { get; init; } = 10_000_000;
    public int MaxArgon2Iterations          { get; init; } = 64;
    public int MaxArgon2MemorySizeKb        { get; init; } = 1_048_576;
    public int MaxArgon2DegreeOfParallelism { get; init; } = 64;
    public int MaxWrappedKeyLength          { get; init; } = 4_096;
    public int MaxEncapsulationLength       { get; init; } = 4_096;
}
```

`init` accessors on `netstandard2.0` require `IsExternalInit`, which PolySharp supplies — already
referenced by FEATURE-67FD. Same for the `record` below.

### Header record

```csharp
public sealed record EncryptedDataHeader
{
    public required EncryptionMethod Method { get; init; }
    public required byte FormatVersion { get; init; }
    public required Cipher Cipher { get; init; }
    public required int HeaderLength { get; init; }      // == payload offset

    public MLKemParameterSet? MLKemParameterSet { get; init; }
    public int? Pbkdf2Iterations { get; init; }
    public int? Argon2Iterations { get; init; }
    public int? Argon2MemorySizeKb { get; init; }
    public int? Argon2DegreeOfParallelism { get; init; }
    public int? WrappedKeyLength { get; init; }          // RSA
    public int? EncapsulationLength { get; init; }       // ML-KEM
}
```

Nullable properties are populated only for the methods they apply to; XML docs must say so
per-property. `HeaderLength` doubles as the payload offset. The header carries no secret — salt and
nonce are omitted deliberately, as exposing them serves no caller purpose.

### Exceptions

```csharp
public abstract class DataEncryptionException : Exception          // (message) and (message, inner)
public sealed class DataEncryptionFormatException : DataEncryptionException
public sealed class DataDecryptionException      : DataEncryptionException
```

Documented mapping — this table is the contract the malformed-input sweep in FEATURE-11B6 asserts:

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
| Key-confirmation tag mismatch | `DataDecryptionException` |
| GCM authentication failure (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| RSA OAEP unwrap failure (`CryptographicException`) | `DataDecryptionException`, wrapping it |
| Malformed / undecryptable private-key PEM | propagates from Enigma.Core (`ArgumentException` / `CryptographicException`) — **not** wrapped, since it is a credential-supply error, not a file-content error |
| Null / empty / out-of-range arguments | `ArgumentNullException` / `ArgumentException` / `ArgumentOutOfRangeException` |
| Cancellation | `OperationCanceledException` |

### Service interfaces

```csharp
public interface IPbkdf2DataEncryptionService
{
    Task EncryptAsync(Stream input, Stream output, Cipher cipher, byte[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    Task EncryptAsync(Stream input, Stream output, Cipher cipher, char[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    Task DecryptAsync(Stream input, Stream output, byte[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    Task DecryptAsync(Stream input, Stream output, char[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);
}

public interface IArgon2DataEncryptionService
{
    Task EncryptAsync(Stream input, Stream output, Cipher cipher, byte[] password,
        int iterations = DataEncryptionDefaults.Argon2Iterations,
        int memorySizeKb = DataEncryptionDefaults.Argon2MemorySizeKb,
        int degreeOfParallelism = DataEncryptionDefaults.Argon2DegreeOfParallelism,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    // + char[] password overload with the same trailing parameters
    // + DecryptAsync(byte[] password, …) and DecryptAsync(char[] password, …) as for PBKDF2
}

public interface IRsaDataEncryptionService
{
    Task EncryptAsync(Stream input, Stream output, Cipher cipher, string publicKeyPem,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    Task DecryptAsync(Stream input, Stream output, string privateKeyPem,
        char[]? keyPassword = null, DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);
}

public interface IMLKemDataEncryptionService
{
    Task EncryptAsync(Stream input, Stream output, Cipher cipher, byte[] publicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    // Parameter set is read from the header — deliberately not a decrypt parameter.
    Task DecryptAsync(Stream input, Stream output, byte[] privateKey,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);
}

public interface IEncryptedDataInspector
{
    Task<EncryptedDataHeader> ReadHeaderAsync(Stream input,
        DataEncryptionLimits? limits = null, CancellationToken cancellationToken = default);
}
```

`limits: null` means `DataEncryptionLimits.Default`. Document that on every `DecryptAsync`.

`char[]` overloads UTF-8-encode into a temporary `byte[]`, delegate to the `byte[]` overload, and
**clear the temporary buffer in a `finally`**. The caller's own array is never mutated or cleared —
the caller owns its lifetime, matching Enigma.Core's convention.

XML docs must state, on every method:

- `IProgress<int>` reports **payload bytes processed**, forwarded from Enigma.Core; header bytes are
  **not** counted.
- Neither stream is disposed; positions are left wherever the operation ended.
- Decryption does **not** require a seekable input stream.
- Key material derived internally is cleared; caller-supplied credentials are not.

### Inspector semantics

`ReadHeaderAsync` consumes the header from the stream. **If the stream is seekable, the original
position is restored before returning**; if it is not, the stream is left positioned at the payload
and the XML doc must say so explicitly, since the caller then cannot re-read the header.

### File-path extensions

```csharp
public static class DataEncryptionFileExtensions
{
    // One pair per service, e.g.:
    public static Task EncryptFileAsync(this IPbkdf2DataEncryptionService service,
        string inputPath, string outputPath, Cipher cipher, byte[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);

    public static Task DecryptFileAsync(this IPbkdf2DataEncryptionService service,
        string inputPath, string outputPath, byte[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null, CancellationToken cancellationToken = default);
    // … and the equivalents for Argon2 / RSA / ML-KEM
}
```

Documented, deliberate semantics — all three must appear in the XML docs:

1. Input opened `FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, useAsync: true`.
2. Output opened `FileMode.Create` (create-or-**overwrite**), `FileAccess.Write, FileShare.None,
   bufferSize: 4096, useAsync: true`.
3. **On any failure — including cancellation — the partial output file is deleted** before the
   exception propagates. This fixes a real trap in the predecessor, which leaves a truncated
   plaintext behind after a failed decrypt. A best-effort delete: a failure to delete must not mask
   the original exception.

Per the `csharp-extension-methods` skill these are extension methods on the service interfaces, so
they compose with any implementation, including a test double.

### DI registration

```csharp
public static IServiceCollection AddEnigmaDataEncryption(this IServiceCollection services)
```

- Null-guard `services`.
- `TryAddSingleton` the **Enigma.Core factories** the services depend on — Enigma.Core deliberately
  ships no `AddEnigmaCore`, so this is our responsibility. All are `sealed` with implicit
  parameterless constructors, verified against Enigma.Core 1.0.0:
  `IBlockCipherServiceFactory` → `BlockCipherServiceFactory`,
  `IPbkdf2ServiceFactory` → `Pbkdf2ServiceFactory`,
  `IArgon2ServiceFactory` → `Argon2ServiceFactory`,
  `IPublicKeyServiceFactory` → `PublicKeyServiceFactory`,
  `IMLKemServiceFactory` → `MLKemServiceFactory`,
  `IHmacServiceFactory` → `HmacServiceFactory`.
- `TryAddSingleton` the internal `IRandomSource` → `RandomSource`.
- `TryAddSingleton` the five own services. **Singleton** is correct: every one is stateless and
  thread-safe, a claim the thread-safety suite in FEATURE-11B6 substantiates.
- `TryAdd*` throughout, so a consumer who has already registered their own Enigma.Core factories
  keeps them.
- Return `services` for chaining.

### Internal RNG seam

```csharp
internal interface IRandomSource
{
    byte[] GenerateRandomBytes(int size);
}

internal sealed class RandomSource : IRandomSource
{
    public byte[] GenerateRandomBytes(int size) => RandomUtils.GenerateRandomBytes(size);
}
```

Each service takes `IRandomSource` through its constructor. Provide a public parameterless (or
factory-only) construction path so the type is usable without DI, and an internal constructor taking
`IRandomSource` for tests. `[InternalsVisibleTo("Enigma.DataEncryption.UnitTests")]` is already in
place from FEATURE-67FD.

This seam exists so FEATURE-11B6's golden-vector tests can pin the **encrypt** path byte-for-byte.
It is deliberately internal: a public hook for injecting randomness into a cryptography library is a
footgun.

## Part 3 — Public-surface guard test

`tests/Enigma.DataEncryption.UnitTests/Api/BouncyCastleIsolationTests.cs`, modelled on
`Enigma.Core`'s equivalent at
`/home/jo/Dev/Enigma.Core/tests/Enigma.Core.UnitTests/Api/BouncyCastleIsolationTests.cs`.

Walk every **exported** type and, for each, its public/protected constructors, methods, properties,
fields, events and generic arguments, plus base types and implemented interfaces. Fail if any
`Org.BouncyCastle.*` type appears anywhere. Read the real test in Enigma.Core first and mirror its
traversal rather than inventing a weaker one.

## Out of scope

- Any behaviour. Every implementation body throws `NotImplementedException`.
- Golden-vector fixtures, round-trip tests, malformed-input sweep, thread-safety tests — FEATURE-11B6.
- `docs/guides/`, `README.md`, `RELEASENOTES.md` — FEATURE-07DA.
- The hybrid method and the legacy reader — FEATURE-5A30 / FEATURE-136E; this dev only **reserves**
  `0x05` and `0x01`–`0x0F` in the spec text.

## Acceptance criteria

1. `docs/format.md` exists and specifies: the common prefix; all four method bodies with exact offsets
   and sizes; little-endian `Int32` encoding stated explicitly; the fixed-parameter table; the AAD
   rule; the key-confirmation derivation and its two documented consequences (key commitment, and the
   header-only password-guessing note); the limits table; the canonical encrypt/decrypt operation
   order; the reserved `0x05` method and `0x01`–`0x0F` version range; and the `memorySizeKb` divergence
   from the predecessor.
2. Every type in the Layout section exists with the signatures above.
3. `MLKemParameterSet` is Enigma.Core's type — no duplicate enum in this library.
4. **Every** public type and member carries an XML doc comment; the documented per-method notes
   (progress semantics, stream ownership, seekability, key clearing, `limits: null` default) are
   present.
5. `dotnet build -c Release` succeeds with **zero warnings** on all three library TFMs — including
   `GenerateDocumentationFile`, so a missing XML comment fails the build.
6. `AddEnigmaDataEncryption()` resolves all five services from a real `ServiceCollection`, and all
   registrations use `TryAdd*`.
7. `BouncyCastleIsolationTests` passes, and its traversal covers members as thoroughly as Enigma.Core's.
8. Full suite green (the smoke test, the guard test, and the DI resolution test). No test asserts
   behaviour that is still `NotImplementedException`.
9. `docs/format.md` and the code agree on every constant. A discrepancy here is the most expensive
   defect this dev can ship — cross-check the offset arithmetic field by field.

## Verification

```bash
dotnet build Enigma.DataEncryption.slnx -c Release
dotnet test --solution Enigma.DataEncryption.slnx -c Release
```

Then re-read `docs/format.md` against `DataEncryptionDefaults` and each service's header-field list,
confirming every offset, size and default matches.

## Notes for the implementer

- Header lengths to verify arithmetically: PBKDF2 **53**, Argon2 **61**, RSA **37 + N**, ML-KEM
  **38 + N**.
- `PaddingScheme.None` exists in Enigma.Core and is the right thing to pass for GCM. Padding is
  ignored for GCM either way; passing `None` explicitly documents that it plays no role.
- `GcmMacSize.MaxBits` is `128` — reference the constant rather than the literal where practical.
- Reserving `0x05` costs nothing now and avoids a format-version bump later.
