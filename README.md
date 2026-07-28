# Enigma.DataEncryption

[![NuGet](https://img.shields.io/nuget/v/Enigma.DataEncryption.svg)](https://www.nuget.org/packages/Enigma.DataEncryption)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.md)

Enigma.DataEncryption encrypts arbitrary data and streams into a **self-describing binary container** — a
header carrying everything a reader needs to decrypt, followed by an AEAD payload. The whole surface follows
one idiom: pick the service that matches your credential — a password, an RSA key pair, a post-quantum
ML-KEM key pair, or both key pairs together — then hand it an input stream, an output stream and that
credential. Each service derives, transports or combines a 32-byte data key and encrypts the payload with a
256-bit cipher in GCM mode, writing the
salt, costs and cipher choice into the header, so decryption needs nothing but the container and the
credential. It is built on [Enigma.Core](https://www.nuget.org/packages/Enigma.Core), which supplies every
cryptographic primitive; BouncyCastle backs Enigma.Core but never appears on this library's public surface.

> **What's new in 1.0** — first release: five credential types including post-quantum ML-KEM and a true
> RSA + ML-KEM hybrid, over one authenticated, key-committing container format. See
> [RELEASENOTES.md](RELEASENOTES.md).

## Features

- **Password-based encryption** — `IPbkdf2DataEncryptionService` (PBKDF2-HMAC-SHA256) and
  `IArgon2DataEncryptionService` (Argon2id v1.3, memory-hard and recommended for new work), each taking a
  `byte[]` or `char[]` password and writing its cost parameters into the header.
- **RSA encryption** — `IRsaDataEncryptionService` transports the data key under RSAES-OAEP-SHA256, taking
  PEM-encoded keys directly, including password-protected private-key PEMs.
- **Post-quantum ML-KEM encryption** — `IMLKemDataEncryptionService` establishes the data key by ML-KEM key
  encapsulation (FIPS 203) at parameter set 512, 768 or 1024.
- **True RSA + ML-KEM hybrid** — `IHybridDataEncryptionService` transports a secret under **each** primitive
  and combines both into the data key with a split-key PRF, so a container stays secure as long as *either*
  primitive holds. Breaking RSA with a quantum computer is not enough, and neither is a classical break of
  ML-KEM. Both private keys are required to decrypt.
- **Four AEAD ciphers** — AES-256, Twofish-256, Serpent-256 and Camellia-256, each in GCM mode, chosen per
  call through the `Cipher` enum.
- **An authenticated header** — the **complete header is passed as GCM associated data**, so editing any
  byte of it, the cipher and iteration count included, is an authentication failure rather than a weaker
  decryption. A 16-byte **key-confirmation tag** gives fast, uniform wrong-credential detection before a
  payload byte is read, and makes the construction key-committing, which plain GCM is not.
- **Bounded hostile input** — every cost and length field read from a header is checked against
  `DataEncryptionLimits` before any allocation or key derivation, so the cost of decrypting a container is
  capped by the reader, not dictated by whoever wrote it. Pass stricter limits to any decrypt call.
- **Header inspection without decryption** — `IEncryptedDataInspector` returns a parsed
  `EncryptedDataHeader` with no credential at all, for detect-then-dispatch and for gating on cost.
- **File-path helpers** — fourteen `DataEncryptionFileExtensions` wrappers over the five methods, which open
  asynchronous `FileStream`s, create or overwrite the output, and delete a partial output on any failure.
- **Dependency injection in one call** — `AddEnigmaDataEncryption()` registers all six services as
  singletons via `TryAdd`, so any registration can be overridden.

### Asynchronous, cancellable, observable

Every operation is `async` and takes an optional `IProgress<int>` reporting payload bytes processed, plus a
`CancellationToken`. Nothing is buffered whole: encrypting a multi-gigabyte file costs the same memory as
encrypting a short string. All six services are stateless and safe for concurrent use, so one instance can
be shared across an application.

## Installation

```bash
dotnet add package Enigma.DataEncryption
```

Targets **.NET Standard 2.0**, **.NET 8.0**, and **.NET 10.0**; built on Enigma.Core 1.0.0.

## Quick start

Encrypt a stream under a password with Argon2id and AES-256-GCM, then read it back — the cost parameters
and salt travel in the container, so decryption takes only the password:

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();

using MemoryStream input = new(Encoding.UTF8.GetBytes("Attack at dawn."));
using MemoryStream container = new();
await service.EncryptAsync(input, container, Cipher.Aes256Gcm, password);

container.Position = 0;
using MemoryStream recovered = new();
await service.DecryptAsync(container, recovered, password);

Console.WriteLine(Encoding.UTF8.GetString(recovered.ToArray()));  // Attack at dawn.
```

## Documentation

Per-category guides — each with the supported operations, the key types, and copy-pasteable C# samples
verified against the public API — live under `docs/guides/` in the repository, indexed by
`docs/guides/README.md`. They cover password-based encryption, RSA, ML-KEM, the RSA + ML-KEM hybrid, header
inspection, file operations, and dependency injection. The normative specification of the container format — every offset,
size and constant, the header-authentication rule, the key-confirmation construction, the limits and the
error mapping — is `docs/format.md`, also in the repository.

## License

Enigma.DataEncryption is released under the [MIT License](LICENSE.md).
