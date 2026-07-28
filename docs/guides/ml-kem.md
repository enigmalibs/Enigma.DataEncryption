# ML-KEM encryption (post-quantum)

Enigma.DataEncryption encrypts data for the holder of an **ML-KEM** (FIPS 203) private key through
`IMLKemDataEncryptionService`. You create the service (directly with `new`, or resolve it from a
container), hand it an input stream, an output stream, a cipher, the recipient's **raw public key bytes**
and the parameter set, and it writes a self-describing container that only the matching private key can
open.

This is the one method that draws no key material of its own. ML-KEM *encapsulation* produces a
ciphertext and a uniformly random 32-byte shared secret at the same time; that secret **is** the data
key, used directly with no further derivation. FIPS 203 shared secrets are exactly what a 256-bit key
needs, and the context binding a KDF would normally add is already achieved by passing the **complete
header as GCM associated data** — so any header edit is an authentication failure.

Everything is stream-based and asynchronous: encrypting a multi-gigabyte file uses the same constant
memory as encrypting a short string. The lattice operation is a fixed, fast prelude that touches only the
32-byte secret.

## Supported parameter sets

| Parameter set | NIST category | Public key | Private key | Header encapsulation | Notes |
|---------------|---------------|-----------:|------------:|---------------------:|-------|
| `MLKemParameterSet.MLKem512` | 1 | 800 B | 1,632 B | 768 B | Smallest containers. Choose it only when size genuinely dominates. |
| `MLKemParameterSet.MLKem768` | 3 | 1,184 B | 2,400 B | 1,088 B | The balanced choice, and what most post-quantum guidance recommends as a general default. |
| `MLKemParameterSet.MLKem1024` | 5 | 1,568 B | 3,168 B | 1,568 B | **This library's default.** The largest margin, at ~1.5 KiB of header. |

`MLKemParameterSet` is Enigma.Core's enum (`Enigma.Core.Asymmetric.Pqc`), reused here rather than
duplicated, so the same value names key generation and encryption.

`EncryptAsync` defaults `parameterSet` to `MLKemParameterSet.MLKem1024` — the conservative choice, since
a container outlives the decision that made it. Note that **Enigma.Core's own
`CreateMLKemService` defaults to `MLKem768` instead**, so if you rely on both defaults at once you will
generate a 768 key pair and try to encapsulate it as 1024, which throws `ArgumentException`. Name the
parameter set explicitly on both sides and the mismatch cannot arise.

`DecryptAsync` takes **no** parameter set. The container records which one it was encapsulated under, so
accepting a second opinion could only introduce a disagreement.

The parameter set is the only choice on the ML-KEM side; the data-key size (32 bytes), nonce size (12
bytes) and tag size (128 bits) are fixed invariants of the format. The other degree of freedom is
`cipher`, which selects the 256-bit GCM cipher protecting the payload.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `IMLKemDataEncryptionService` | `Enigma.DataEncryption` | The ML-KEM service. DI-friendly. |
| `MLKemDataEncryptionService` | `Enigma.DataEncryption` | Concrete implementation. Create with `new` — the parameterless constructor wires Enigma.Core's default factories. |
| `MLKemParameterSet` | `Enigma.Core.Asymmetric.Pqc` | The parameter set: `MLKem512`, `MLKem768`, `MLKem1024`. |
| `Cipher` | `Enigma.DataEncryption` | Which 256-bit GCM cipher protects the payload: `Aes256Gcm`, `Twofish256Gcm`, `Serpent256Gcm`, `Camellia256Gcm`. |
| `DataEncryptionLimits` | `Enigma.DataEncryption` | Bounds the header's encapsulation length before it is allocated. `MaxEncapsulationLength` defaults to 4,096 bytes. |
| `DataDecryptionException` | `Enigma.DataEncryption` | The private key does not open this container, or the payload failed authentication. |
| `DataEncryptionFormatException` | `Enigma.DataEncryption` | The input is not an ML-KEM container, its parameter-set byte is undefined, or its encapsulation length is out of bounds. |
| `IMLKemService` | `Enigma.Core.Asymmetric.Pqc` | Enigma.Core's ML-KEM service — this is where key pairs come from. |
| `MLKemServiceFactory` | `Enigma.Core.Asymmetric.Pqc` | Concrete factory for the above. Create with `new`; implements `IMLKemServiceFactory`. |

The two methods:

```csharp
Task EncryptAsync(
    Stream input,
    Stream output,
    Cipher cipher,
    byte[] publicKey,
    MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);

Task DecryptAsync(
    Stream input,
    Stream output,
    byte[] privateKey,
    DataEncryptionLimits? limits = null,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

Neither disposes either stream, and both leave the streams wherever the operation ended. Caller-supplied
key arrays are never mutated and never cleared. The service is stateless and safe for concurrent use, so
one instance can be shared across an application; `MLKemDataEncryptionService` can equally be registered
against `IMLKemDataEncryptionService` in a Microsoft.Extensions.DependencyInjection container (see
[Dependency injection](dependency-injection.md)).

## Usage

### Generate a key pair

Key generation belongs to Enigma.Core. Both keys come back as raw FIPS 203 byte encodings — the private
key is the **expanded** decapsulation key, not a seed, so it is directly usable:

```csharp
using System;
using Enigma.Core.Asymmetric.Pqc;

IMLKemService kem = new MLKemServiceFactory()
    .CreateMLKemService(MLKemParameterSet.MLKem1024);

(byte[] publicKey, byte[] privateKey) = kem.GenerateKeyPair();

Console.WriteLine($"public {publicKey.Length} B, private {privateKey.Length} B");  // 1568 B, 3168 B
```

Generation is fast — milliseconds, not the seconds RSA takes at comparable strength.

### Encrypt and decrypt in memory

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption;

IMLKemService kem = new MLKemServiceFactory()
    .CreateMLKemService(MLKemParameterSet.MLKem1024);
(byte[] publicKey, byte[] privateKey) = kem.GenerateKeyPair();

IMLKemDataEncryptionService service = new MLKemDataEncryptionService();

byte[] plaintext = Encoding.UTF8.GetBytes("Attack at dawn.");

using MemoryStream input = new(plaintext);
using MemoryStream container = new();

await service.EncryptAsync(
    input, container, Cipher.Aes256Gcm, publicKey, MLKemParameterSet.MLKem1024);

// Rewind the container before reading it back.
container.Position = 0;

using MemoryStream recovered = new();
await service.DecryptAsync(container, recovered, privateKey);

Console.WriteLine(Encoding.UTF8.GetString(recovered.ToArray()));  // Attack at dawn.
```

Note the asymmetry: the parameter set is named on encrypt and absent on decrypt, because by then it is in
the header.

### Choose a smaller parameter set

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption;

// Both sides name MLKem768 — the key pair and the encapsulation must agree.
IMLKemService kem = new MLKemServiceFactory()
    .CreateMLKemService(MLKemParameterSet.MLKem768);
(byte[] publicKey, byte[] privateKey) = kem.GenerateKeyPair();

IMLKemDataEncryptionService service = new MLKemDataEncryptionService();

using MemoryStream input = new(Encoding.UTF8.GetBytes("Attack at dawn."));
using MemoryStream container = new();

await service.EncryptAsync(
    input, container, Cipher.Aes256Gcm, publicKey, MLKemParameterSet.MLKem768);

Console.WriteLine($"{container.Length} bytes");  // 38 + 1088 header + payload + 16-byte tag
```

Handing a key of one parameter set to another set's encapsulation throws `ArgumentException` on
`publicKey` — the length check catches it immediately.

### Persist the keys — protecting the private key at rest

ML-KEM keys are raw `byte[]`, with no PEM or container format of their own. The public key is not secret,
so writing it out is just a file write. **The private key is secret**, and the documented pattern is to
protect it with this library's own password-based service — a 3,168-byte private key is exactly the kind
of small payload the Argon2 service handles well:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption;

IMLKemService kem = new MLKemServiceFactory()
    .CreateMLKemService(MLKemParameterSet.MLKem1024);
(byte[] publicKey, byte[] privateKey) = kem.GenerateKeyPair();

// The public key needs no protection — it is what senders use.
File.WriteAllBytes("recipient.mlkem.pub", publicKey);

// The private key does. Encrypt it under a password with Argon2id.
IArgon2DataEncryptionService passwordService = new Argon2DataEncryptionService();
char[] keyPassword = "protect-the-key-file".ToCharArray();

try
{
    using MemoryStream keyBytes = new(privateKey);
    using FileStream keyFile = File.Create("recipient.mlkem.key");

    await passwordService.EncryptAsync(keyBytes, keyFile, Cipher.Aes256Gcm, keyPassword);
}
finally
{
    Array.Clear(keyPassword, 0, keyPassword.Length);
}
```

and to read it back, decrypt the key file first, then use the recovered bytes:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService passwordService = new Argon2DataEncryptionService();
IMLKemDataEncryptionService service = new MLKemDataEncryptionService();

char[] keyPassword = "protect-the-key-file".ToCharArray();
byte[]? privateKey = null;

try
{
    using (FileStream keyFile = File.OpenRead("recipient.mlkem.key"))
    using (MemoryStream keyBytes = new())
    {
        await passwordService.DecryptAsync(keyFile, keyBytes, keyPassword);
        privateKey = keyBytes.ToArray();
    }

    using FileStream container = File.OpenRead("secret.bin");
    using FileStream output = File.Create("secret.txt");

    await service.DecryptAsync(container, output, privateKey);
}
finally
{
    Array.Clear(keyPassword, 0, keyPassword.Length);
    if (privateKey is not null) Array.Clear(privateKey, 0, privateKey.Length);
}
```

The key file is an ordinary Argon2 container, so everything in [Password-based
encryption](password-based.md) applies to it — including that a wrong password fails fast, before any
payload byte is read.

### Handle the failure modes

FIPS 203 specifies **implicit rejection**: decapsulating with the wrong private key does not fail, it
returns a wrong-but-well-formed 32-byte secret. Without a check, the payload GCM tag would eventually
catch that — but only after reading the whole payload, and with a failure that looks like corruption
rather than a wrong key. The header's **key-confirmation tag** is what turns it into a clean, immediate
error:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IMLKemDataEncryptionService service = new MLKemDataEncryptionService();
byte[] privateKey = File.ReadAllBytes("recipient.mlkem.key.raw");

using FileStream container = File.OpenRead("secret.bin");
using MemoryStream recovered = new();

try
{
    await service.DecryptAsync(container, recovered, privateKey);
}
catch (DataEncryptionFormatException ex)
{
    Console.WriteLine($"Not an ML-KEM container this library can read: {ex.Message}");
}
catch (DataDecryptionException ex)
{
    // Wrong key, a key for another parameter set, a malformed key, or a tampered container.
    Console.WriteLine($"This key does not open it: {ex.InnerException?.Message ?? ex.Message}");
}
```

`DataDecryptionException` is deliberately broad on this path, and the two directions are **not**
symmetric:

- **Encrypt** takes the public key and nothing else, so an unusable key can only be the caller's fault:
  that is an `ArgumentException` on `publicKey`.
- **Decrypt** cannot draw the same line. Enigma.Core reports a malformed private key, a key for a
  different parameter set, and a container whose parameter-set byte has been edited *identically* — the
  caller's fault and the file's fault, indistinguishable without matching on message text. All three
  therefore surface as `DataDecryptionException`, with the original exception kept as `InnerException`,
  because announcing an argument error for a tampered file is the worse of the two mistakes.

### Bound the encapsulation length

The header's encapsulation length is attacker-controlled, so it is bounded before the buffer is allocated
or read. `MaxEncapsulationLength` defaults to 4,096 bytes; the true maximum any parameter set produces is
1,568:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IMLKemDataEncryptionService service = new MLKemDataEncryptionService();
byte[] privateKey = File.ReadAllBytes("recipient.mlkem.key.raw");

// This deployment only ever issues ML-KEM-1024 keys, whose encapsulation is 1568 bytes.
DataEncryptionLimits limits = new() { MaxEncapsulationLength = 1_568 };

using FileStream container = File.OpenRead("secret.bin");
using MemoryStream recovered = new();

await service.DecryptAsync(container, recovered, privateKey, limits);
```

Passing `null` uses `DataEncryptionLimits.Default`. A length outside the bound raises
`DataEncryptionFormatException` before anything is allocated.

### Progress and cancellation

Every operation takes an optional `IProgress<int>` and a `CancellationToken`. Progress reports
**increments of payload bytes processed** — the values sum to the payload length, they are not a running
total and not a percentage — and the header, encapsulation included, is never counted.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption;

IMLKemDataEncryptionService service = new MLKemDataEncryptionService();
byte[] publicKey = File.ReadAllBytes("recipient.mlkem.pub");

using FileStream input = File.OpenRead("large-input.bin");
using FileStream output = File.Create("large-input.bin.enc");

long total = input.Length;
long done = 0;
var progress = new Progress<int>(bytes =>
{
    done += bytes;
    Console.WriteLine($"{done * 100 / total}%");
});

using CancellationTokenSource cts = new();

await service.EncryptAsync(
    input, output, Cipher.Aes256Gcm, publicKey, MLKemParameterSet.MLKem1024, progress, cts.Token);
```

Cancellation surfaces as `OperationCanceledException`. For file-to-file work, prefer the extension
methods in [File operations](file-operations.md), which delete the partial output on any failure.

## Notes

- **This is post-quantum key establishment, not a post-quantum signature.** Anyone with the recipient's
  public key can produce a valid container, so a successful decrypt proves the container was made for you
  — not who made it.
- **This method is not hybrid.** It wraps the data key under ML-KEM alone, so a container is only as strong
  as ML-KEM: a classical cryptanalytic break of the lattice problem would open it. If the data must survive
  that possibility as well as a quantum computer, use
  [`IHybridDataEncryptionService`](hybrid.md) instead, which combines an ML-KEM secret with an
  RSA-transported one so that breaking one primitive is not enough.
- **The shared secret is used as the data key with no additional derivation.** That is a deliberate,
  documented choice, sound because FIPS 203 secrets are uniformly random 32-byte values and the complete
  header is authenticated as associated data.
- **Match the parameter set on both sides.** A key pair is generated *for* a parameter set; the same
  value must be passed to `EncryptAsync`. Our default is `MLKem1024`, Enigma.Core's factory default is
  `MLKem768` — naming it explicitly on both calls is the habit that prevents the mismatch.
- **Keys are raw bytes with no envelope of their own.** There is nothing self-describing about a
  `byte[]`, so record which parameter set a stored key belongs to — the file name is a fine place — and
  encrypt the private key at rest, as shown above.
- **The input stream is read to its end** from wherever it is positioned. Position it at the start of the
  data before calling, and rewind a `MemoryStream` you have just written before decrypting it.
- **The container stream need not be seekable on decrypt.** The header is read forward exactly once and
  the payload is streamed from where it ended, so a network stream works.
- **A container from another method is a format error, not a misparse.** This service reads only method
  byte `0x04`. Use [`IEncryptedDataInspector`](header-inspection.md) when you do not know which method
  produced a container — it also reports the container's parameter set, so you can check you hold the
  right key before trying it.
