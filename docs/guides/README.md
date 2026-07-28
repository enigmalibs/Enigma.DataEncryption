# Enigma.DataEncryption — Guides & Samples

Per-category guides for **Enigma.DataEncryption**, a .NET library that encrypts arbitrary data and
streams into a self-describing binary container — a header carrying everything a reader needs to decrypt,
followed by an AEAD payload.

Every category follows the same idiom. You pick the service for your credential —
`IPbkdf2DataEncryptionService` or `IArgon2DataEncryptionService` for a password,
`IRsaDataEncryptionService` for an RSA key pair, `IMLKemDataEncryptionService` for a post-quantum ML-KEM
key pair, `IHybridDataEncryptionService` for both key pairs together — and call `EncryptAsync` or
`DecryptAsync` on it with an input stream, an output stream and the credential. Each of the five derives,
transports or combines a 32-byte data key, then encrypts the payload with a
256-bit AEAD cipher in GCM mode, passing the **complete header as associated data** so any header edit is
an authentication failure. Every service is stateless, thread-safe, fully asynchronous, and takes an
optional `IProgress<int>` and `CancellationToken`.

Obtain a service either way: `new Argon2DataEncryptionService()` needs no container, or call
`services.AddEnigmaDataEncryption()` once and inject the interfaces. All public types live in the flat
`Enigma.DataEncryption` namespace, so one `using` covers everything (the DI extension excepted, which sits
in `Microsoft.Extensions.DependencyInjection` by convention).

Each guide follows the same shape — **supported operations → key types → copy-pasteable usage samples** —
and every snippet targets the real public API.

## Encrypting and decrypting

- [Password-based encryption](password-based.md) — `IPbkdf2DataEncryptionService` and
  `IArgon2DataEncryptionService`: choosing and tuning the KDF cost parameters, `byte[]` versus `char[]`
  passwords and clearing them, and bounding a hostile header's costs before they are paid.
- [RSA encryption](rsa.md) — `IRsaDataEncryptionService`: generating a key pair with Enigma.Core's
  `IPublicKeyService`, PEM handling, encrypted private-key PEMs and `keyPassword`, and the two distinct
  ways a bad key surfaces.
- [ML-KEM encryption (post-quantum)](ml-kem.md) — `IMLKemDataEncryptionService`: the three parameter sets
  and how to choose, generating keys with Enigma.Core's `IMLKemService`, and persisting raw `byte[]` keys
  by protecting the private key at rest with this library's own password service.
- [Hybrid RSA + ML-KEM encryption](hybrid.md) — `IHybridDataEncryptionService`: the strongest option the
  library offers, and the only method needing two credentials. How the data key is combined from a secret
  transported under each primitive so the container survives a break of either one, why the two halves fail
  in different places, and bounding both of the header's length fields.

## Working with containers

- [Header inspection](header-inspection.md) — `IEncryptedDataInspector` and `EncryptedDataHeader`: reading
  a container's header with no credential, the detect-then-dispatch pattern, gating on derivation cost, and
  the seekable versus non-seekable stream-position behaviour.
- [File operations](file-operations.md) — `DataEncryptionFileExtensions`: the fourteen file-path wrappers and
  their three documented semantics — asynchronous `FileStream`s, create-or-overwrite output, and the
  partial output deleted on any failure including cancellation.

## Wiring it up

- [Dependency injection](dependency-injection.md) — `AddEnigmaDataEncryption()`: what it registers
  including the Enigma.Core factories, why every lifetime is singleton, how `TryAdd` lets you override any
  of them, and how to use the library with no container at all.

## The binary format

- [**`../format.md`**](../format.md) — the **normative specification** of the container format: every
  offset, size, constant, the header-authentication rule, the key-confirmation construction, the limits and
  the error mapping. It is the contract that code and documentation both answer to.

The guides above are *usage*; `format.md` is the *spec*. Read it when you need to know what is on the
wire — implementing a reader in another language, auditing the construction, or checking a byte offset. You
do not need it to use the library.
