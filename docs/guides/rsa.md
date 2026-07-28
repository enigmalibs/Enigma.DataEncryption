# RSA encryption

Enigma.DataEncryption encrypts data for the holder of an RSA private key through
`IRsaDataEncryptionService`. You create the service (directly with `new`, or resolve it from a
container), hand it an input stream, an output stream, a cipher and the recipient's **PEM-encoded public
key**, and it writes a self-describing container that only the matching private key can open.

RSA never touches your data. Each call generates a fresh 32-byte data key, wraps *that* under
**RSAES-OAEP with SHA-256**, and stores the wrapped key in the header; the payload itself is encrypted
symmetrically with the 256-bit GCM cipher you chose. So the RSA key size bounds nothing about your file —
a 2048-bit key encrypts a terabyte as happily as a sentence — and the **complete header is passed as GCM
associated data**, so tampering with the wrapped key or any other header byte is an authentication
failure.

Everything is stream-based and asynchronous: encrypting a multi-gigabyte file uses the same constant
memory as encrypting a short string, because only the 32-byte data key is ever held in full.

## Supported operations

| Operation | Method | Credential | Notes |
|-----------|--------|------------|-------|
| Encrypt | `EncryptAsync` | The recipient's **public** key PEM | Anyone holding the public key can produce a container. No signature is added — this gives confidentiality, not authenticity. |
| Decrypt | `DecryptAsync` | The recipient's **private** key PEM, plus `keyPassword` if the PEM is encrypted | The wrapped key's length is read from the header, so no key size is passed in. |

The public key may be a `PUBLIC KEY` or an `RSA PUBLIC KEY` PEM. The private key may be an unencrypted
`PRIVATE KEY` PEM, or an AES-256-CBC-encrypted private-key PEM — in which case `keyPassword` is
required, and is a `char[]` the caller owns and clears.

There are no algorithm choices to make on the RSA side: the wrap is always RSAES-OAEP with SHA-256, and
the data-key size (32 bytes), nonce size (12 bytes) and tag size (128 bits) are fixed invariants of the
format. The only degree of freedom is `cipher`, which selects the 256-bit GCM cipher protecting the
payload. **No public-key fingerprint is stored** — an OAEP unwrap already fails fast on the wrong key,
and the header's key-confirmation tag covers wrong-credential detection uniformly across all five
methods.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `IRsaDataEncryptionService` | `Enigma.DataEncryption` | The RSA service. DI-friendly. |
| `RsaDataEncryptionService` | `Enigma.DataEncryption` | Concrete implementation. Create with `new` — the parameterless constructor wires Enigma.Core's default factories. |
| `Cipher` | `Enigma.DataEncryption` | Which 256-bit GCM cipher protects the payload: `Aes256Gcm`, `Twofish256Gcm`, `Serpent256Gcm`, `Camellia256Gcm`. |
| `DataEncryptionLimits` | `Enigma.DataEncryption` | Bounds the header's wrapped-key length before it is allocated. `MaxWrappedKeyLength` defaults to 4,096 bytes. |
| `DataDecryptionException` | `Enigma.DataEncryption` | The private key does not open this container, or the payload failed authentication. |
| `DataEncryptionFormatException` | `Enigma.DataEncryption` | The input is not an RSA container, or its wrapped-key length is out of bounds. |
| `IPublicKeyService` | `Enigma.Core.Asymmetric.PublicKey` | Enigma.Core's RSA service — this is where key pairs come from. |
| `PublicKeyServiceFactory` | `Enigma.Core.Asymmetric.PublicKey` | Concrete factory for the above. Create with `new`; implements `IPublicKeyServiceFactory`. |

The two methods:

```csharp
Task EncryptAsync(
    Stream input,
    Stream output,
    Cipher cipher,
    string publicKeyPem,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);

Task DecryptAsync(
    Stream input,
    Stream output,
    string privateKeyPem,
    char[]? keyPassword = null,
    DataEncryptionLimits? limits = null,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

Neither disposes either stream, and both leave the streams wherever the operation ended. The service is
stateless and safe for concurrent use, so one instance can be shared across an application;
`RsaDataEncryptionService` can equally be registered against `IRsaDataEncryptionService` in a
Microsoft.Extensions.DependencyInjection container (see [Dependency injection](dependency-injection.md)).

## Usage

### Generate a key pair

Key generation belongs to Enigma.Core, not to this library — `IPublicKeyService.GenerateRsaKeyPair`
returns both keys as PEM text, ready to pass straight in:

```csharp
using System;
using Enigma.Core.Asymmetric.PublicKey;

IPublicKeyService publicKeys = new PublicKeyServiceFactory().CreatePublicKeyService();

// keySizeBits defaults to 2048; 3072 or 4096 buy a larger margin at a slower keygen and unwrap.
(string publicKeyPem, string privateKeyPem) = publicKeys.GenerateRsaKeyPair(3072);

Console.WriteLine(publicKeyPem);   // -----BEGIN PUBLIC KEY----- …
Console.WriteLine(privateKeyPem);  // -----BEGIN PRIVATE KEY----- …
```

Distribute `publicKeyPem` freely — it is what senders need. Guard `privateKeyPem`: it is the only thing
that opens the containers.

### Encrypt and decrypt in memory

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption;

IPublicKeyService publicKeys = new PublicKeyServiceFactory().CreatePublicKeyService();
(string publicKeyPem, string privateKeyPem) = publicKeys.GenerateRsaKeyPair(2048);

IRsaDataEncryptionService service = new RsaDataEncryptionService();

byte[] plaintext = Encoding.UTF8.GetBytes("Attack at dawn.");

using MemoryStream input = new(plaintext);
using MemoryStream container = new();

await service.EncryptAsync(input, container, Cipher.Aes256Gcm, publicKeyPem);

// Rewind the container before reading it back.
container.Position = 0;

using MemoryStream recovered = new();
await service.DecryptAsync(container, recovered, privateKeyPem);

Console.WriteLine(Encoding.UTF8.GetString(recovered.ToArray()));  // Attack at dawn.
```

### Work with an encrypted private-key PEM

Passing a passphrase to `GenerateRsaKeyPair` returns the private key as an AES-256-CBC-encrypted PEM.
The same passphrase then goes to `DecryptAsync` as `keyPassword`:

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption;

char[] pemPassphrase = "protect-the-key-file".ToCharArray();

try
{
    IPublicKeyService publicKeys = new PublicKeyServiceFactory().CreatePublicKeyService();
    (string publicKeyPem, string privateKeyPem) =
        publicKeys.GenerateRsaKeyPair(2048, pemPassphrase);

    IRsaDataEncryptionService service = new RsaDataEncryptionService();

    using MemoryStream input = new(Encoding.UTF8.GetBytes("Attack at dawn."));
    using MemoryStream container = new();

    await service.EncryptAsync(input, container, Cipher.Aes256Gcm, publicKeyPem);
    container.Position = 0;

    using MemoryStream recovered = new();
    await service.DecryptAsync(container, recovered, privateKeyPem, keyPassword: pemPassphrase);

    Console.WriteLine(Encoding.UTF8.GetString(recovered.ToArray()));
}
finally
{
    // Neither Enigma.Core nor this library clears a caller-supplied array.
    Array.Clear(pemPassphrase, 0, pemPassphrase.Length);
}
```

Two things are worth knowing about the failure modes here, and they are not symmetric:

- A PEM the library **cannot parse at all** is a credential-supply error, and Enigma.Core's exception
  propagates **unwrapped** — `ArgumentException`, or `FormatException` where the Base64 is invalid. It
  says nothing about the container.
- A PEM that parses but **does not open the container** — the wrong key pair, or an encrypted PEM with a
  wrong or missing `keyPassword` — surfaces as `DataDecryptionException`, with the underlying exception
  preserved as `InnerException`. Enigma.Core reports "wrong private key" and "cannot decrypt this PEM"
  identically, so these two genuinely cannot be split apart without matching on message text, which is
  not a contract worth depending on.

### Handle the failure modes

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IRsaDataEncryptionService service = new RsaDataEncryptionService();
string privateKeyPem = File.ReadAllText("recipient.key");

using FileStream container = File.OpenRead("secret.bin");
using MemoryStream recovered = new();

try
{
    await service.DecryptAsync(container, recovered, privateKeyPem);
}
catch (DataEncryptionFormatException ex)
{
    Console.WriteLine($"Not an RSA container this library can read: {ex.Message}");
}
catch (DataDecryptionException ex)
{
    Console.WriteLine($"This key does not open it: {ex.InnerException?.Message ?? ex.Message}");
}
catch (ArgumentException ex)
{
    Console.WriteLine($"That PEM could not be parsed: {ex.Message}");
}
```

`DataEncryptionFormatException` and `DataDecryptionException` both derive from
`DataEncryptionException`, so catch that instead when the distinction does not matter. Note that
`FormatException` — the other unparseable-PEM outcome — is not an `ArgumentException`, so catch it too if
you accept PEM text from an untrusted source.

### Bound the wrapped-key length

The header's wrapped-key length is attacker-controlled, so it is bounded before the buffer is allocated
or read. `DataEncryptionLimits.MaxWrappedKeyLength` defaults to 4,096 bytes — comfortably above the 512
an RSA-4096 key produces. Tighten it if you know your key size:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IRsaDataEncryptionService service = new RsaDataEncryptionService();
string privateKeyPem = File.ReadAllText("recipient.key");

// This deployment only ever issues RSA-2048 keys, whose wrapped key is 256 bytes.
DataEncryptionLimits limits = new() { MaxWrappedKeyLength = 256 };

using FileStream container = File.OpenRead("secret.bin");
using MemoryStream recovered = new();

await service.DecryptAsync(container, recovered, privateKeyPem, limits: limits);
```

Passing `null` uses `DataEncryptionLimits.Default`. A length outside the bound raises
`DataEncryptionFormatException` before anything is allocated.

### Progress and cancellation

Every operation takes an optional `IProgress<int>` and a `CancellationToken`. Progress reports
**increments of payload bytes processed** — the values sum to the payload length, they are not a running
total and not a percentage — and the header, including the RSA wrap, is never counted.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IRsaDataEncryptionService service = new RsaDataEncryptionService();
string publicKeyPem = File.ReadAllText("recipient.pub");

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
    input, output, Cipher.Aes256Gcm, publicKeyPem, progress, cts.Token);
```

Cancellation surfaces as `OperationCanceledException`. For file-to-file work, prefer the extension
methods in [File operations](file-operations.md), which delete the partial output on any failure.

## Notes

- **This gives confidentiality, not authenticity.** Anyone with the recipient's public key can produce a
  valid container, so a successful decrypt proves the container was made for you — not who made it. Sign
  separately if you need sender authentication.
- **This method is not quantum-resistant.** RSA falls to a sufficiently large quantum computer, so a
  container that must stay confidential beyond that horizon should not rely on RSA alone. Use
  [`IHybridDataEncryptionService`](hybrid.md), which combines an RSA-transported secret with an ML-KEM
  encapsulated one so that breaking either primitive is not enough — or
  [`IMLKemDataEncryptionService`](ml-kem.md) if you are willing to rely on the lattice assumption alone.
- **The RSA operation covers only the 32-byte data key**, so the key size constrains nothing about the
  payload size. Choose the key size for its own reasons; 2048 bits is the practical minimum, 3072 or
  4096 for a longer horizon.
- **The wrapped-key length equals the RSA modulus size in bytes**, so the header is 37 + 256 bytes for
  an RSA-2048 key, 37 + 384 for 3072, and 37 + 512 for 4096. It is the one field of an RSA container
  whose value varies with the credential — and, because OAEP is randomised, the wrapped-key **bytes**
  differ on every call even for identical input and key.
- **Wrong-key detection happens before any payload byte is read.** OAEP unwrap fails fast, and where it
  succeeds the header's key-confirmation tag is verified in constant time immediately afterwards.
- **The input stream is read to its end** from wherever it is positioned. Position it at the start of the
  data before calling, and rewind a `MemoryStream` you have just written before decrypting it.
- **The container stream need not be seekable on decrypt.** The header is read forward exactly once and
  the payload is streamed from where it ended, so a network stream works.
- **A container from another method is a format error, not a misparse.** This service reads only method
  byte `0x03`. Use [`IEncryptedDataInspector`](header-inspection.md) when you do not know which method
  produced a container.
- **PEM text is a `string`, and strings are not clearable.** If that matters to your threat model, note
  that an encrypted private-key PEM plus a `char[]` passphrase keeps the sensitive part in an array you
  *can* clear — as the snippet above does.
