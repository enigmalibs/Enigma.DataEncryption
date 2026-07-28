# Enigma.DataEncryption v1.0.0 Release Notes

The first public release of **Enigma.DataEncryption** — a .NET library that encrypts arbitrary data and
streams into a self-describing binary container: a header carrying everything a reader needs to decrypt,
followed by an AEAD payload. Every credential type follows one idiom — pick the service that matches your
credential, hand it an input stream, an output stream and the credential — and every method derives or
transports or combines a 32-byte data key, then encrypts the payload with a 256-bit block cipher in GCM
mode. It is built on [Enigma.Core](https://www.nuget.org/packages/Enigma.Core), which supplies every
cryptographic primitive; BouncyCastle backs Enigma.Core but never appears on this library's public surface.

## Feature overview

- **Password-based encryption** — `IPbkdf2DataEncryptionService` (PBKDF2-HMAC-SHA256, 600,000 iterations
  by default) and `IArgon2DataEncryptionService` (Argon2id v1.3, 3 passes over 64 MiB across 4 lanes by
  default, RFC 9106's second recommended option). Each call draws a fresh 16-byte salt and writes it with
  the cost parameters into the header, so decryption needs nothing but the container and the password.
  Both accept a `byte[]` or a `char[]` password, and clear the key material they derive.
- **RSA encryption** — `IRsaDataEncryptionService` transports a freshly generated data key under
  RSAES-OAEP-SHA256, taking PEM-encoded keys directly. Encrypted private-key PEMs are supported through
  an optional `keyPassword`.
- **Post-quantum ML-KEM encryption** — `IMLKemDataEncryptionService` establishes the data key by ML-KEM
  key encapsulation (FIPS 203) at parameter set 512, 768 or 1024, taking the encapsulated shared secret
  as the data key directly. FIPS 203 implicit rejection means decapsulation with a wrong key *succeeds*
  and yields a different secret; the header's key-confirmation tag is what turns that into a clean,
  immediate failure.
- **True RSA + ML-KEM hybrid encryption** — `IHybridDataEncryptionService` is the strongest option the
  library offers, and the only method taking two credentials. It wraps a random 32-byte secret under the
  recipient's RSA public key with RSAES-OAEP-SHA256, encapsulates a second secret against their ML-KEM
  public key, and **combines both** into the data key with a split-key PRF — the XOR of two
  domain-separated HMAC-SHA256 outputs, one keyed by each secret, over a transcript binding both
  ciphertexts. If either key is a value the attacker does not hold, the data key is indistinguishable from
  random, so the container survives a quantum break of RSA *and* a classical break of ML-KEM. Both private
  keys are required to decrypt, and they fail in different places: a wrong RSA key is caught by the OAEP
  unwrap, while a wrong ML-KEM key reaches the key-confirmation tag, because implicit rejection lets its
  decapsulation succeed. `docs/format.md` §3.5.1 specifies the combiner and §3.5.2 states its rationale.
- **Four AEAD ciphers** — AES-256, Twofish-256, Serpent-256 and Camellia-256, each in GCM mode with a
  12-byte nonce and a 128-bit tag, selected per call through the `Cipher` enum and recorded in the header.
- **An authenticated, self-describing container** — the **complete header is passed as GCM associated
  data**, so editing any byte of it — the cipher, the iteration count, the salt — is an authentication
  failure rather than a slower or weaker decryption. A 16-byte **key-confirmation tag** in the header
  gives uniform, fast wrong-credential detection before a single payload byte is read, and makes the
  construction key-committing, which plain GCM is not.
- **Bounded, hostile-input-safe reads** — every cost and length field read from a header is validated
  against `DataEncryptionLimits` before any allocation or key-derivation work is done, so the cost of
  decrypting a container is capped by the reader rather than dictated by whoever wrote it. The defaults
  admit at most 10,000,000 PBKDF2 iterations and 1 GiB of Argon2 memory; a header asking for more is
  rejected before a byte is allocated. `DataEncryptionLimits.Default` is the shared instance, and every
  decrypt operation — and the inspector — accepts a stricter one.
- **Header inspection without decryption** — `IEncryptedDataInspector` parses a container's header and
  returns an `EncryptedDataHeader` with no credential at all, for the detect-then-dispatch pattern and for
  gating on derivation cost before you commit to paying it.
- **File-path helpers** — fourteen `DataEncryptionFileExtensions` wrappers covering every method, opening
  asynchronous `FileStream`s, creating or overwriting the output, and deleting a partial output on any
  failure including cancellation.
- **Asynchronous, cancellable, observable** — every operation is `async` and takes an optional
  `IProgress<int>` (payload bytes processed) and a `CancellationToken`. All six services are stateless
  and safe for concurrent use, so a single instance can be shared across an application.
- **Dependency injection in one call** — `AddEnigmaDataEncryption()` registers all six services, and the
  Enigma.Core factories they depend on, as singletons using `TryAdd`, so any of them can be overridden.

## Compatibility

- Targets **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**.
- Built on **Enigma.Core 1.0.0** and **Microsoft.Extensions.DependencyInjection.Abstractions 9.0.18**.
- No target framework was dropped — this is the first release.

### Not compatible with `Enigma.Cryptography.DataEncryption`

Enigma.DataEncryption is the successor to `Enigma.Cryptography.DataEncryption`, but its **binary format is
deliberately different, and containers written by the predecessor cannot be read by this release.** The
format changed in ways that are not expressible as a compatible extension:

- the complete header is now authenticated as AEAD associated data, so every header byte is covered by
  the payload tag;
- a key-confirmation tag was added to the header, making the construction key-committing;
- the RSA data key is wrapped with RSAES-OAEP-SHA256;
- Argon2's memory cost is recorded in **KiB** rather than bytes.

Each of those changes the bytes on the wire. Rather than risk mis-reading an old file, this release rejects
them outright: the format-version byte is `0x10`, and the values `0x01`–`0x0F` are **reserved for legacy
containers**. That reservation is the mechanism by which a future release could add read-only support for
predecessor files without a second format-version bump — a container declaring a reserved version raises
`DataEncryptionFormatException` today rather than being read as something it is not.

`docs/format.md` in the repository is the normative specification of the container format.

## Version

- Initial release: **1.0.0**.
