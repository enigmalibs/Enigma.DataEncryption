# Hybrid RSA + ML-KEM encryption

Enigma.DataEncryption encrypts data under an **RSA key pair and an ML-KEM (FIPS 203) key pair together**
through `IHybridDataEncryptionService`. You create the service (directly with `new`, or resolve it from a
container), hand it an input stream, an output stream, a cipher, **both** of the recipient's public keys and
the ML-KEM parameter set, and it writes a self-describing container that only the matching **pair** of
private keys can open.

This is the strongest option the library offers, and the only method that needs two credentials. Neither
`IRsaDataEncryptionService` nor `IMLKemDataEncryptionService` is "hybrid" in the post-quantum sense — each
wraps the data key under one primitive, so each file is only as strong as that primitive:

- an RSA-only file is broken by a sufficiently large quantum computer;
- an ML-KEM-only file is broken if a classical cryptanalytic break of ML-KEM is found.

The hybrid method transports a secret under **each** primitive and derives the data key from **both**, so the
container stays secure as long as *either* primitive holds. That is what NIST and IETF post-quantum
migration guidance recommends for the transition period.

Everything is stream-based and asynchronous: encrypting a multi-gigabyte file uses the same constant memory
as encrypting a short string. Both public-key operations are a fixed, fast prelude that touches only two
32-byte secrets.

## How the data key is established

Three steps, in this order:

1. A random 32-byte `rsaSecret` is generated and wrapped under the RSA public key with **RSAES-OAEP-SHA256**,
   giving `wrappedRsaSecret`.
2. A `kemSecret` is **encapsulated** against the ML-KEM public key, giving `encapsulation` alongside it.
3. The data key is **combined** from both secrets, bound to both ciphertexts:

   ```text
   T    = LE32(N) ‖ wrappedRsaSecret ‖ LE32(M) ‖ encapsulation

   Krsa = HMAC-SHA256(key: rsaSecret, message: "Enigma.DataEncryption/hybrid/rsa/v1"   ‖ T)
   Kkem = HMAC-SHA256(key: kemSecret, message: "Enigma.DataEncryption/hybrid/mlkem/v1" ‖ T)

   K    = Krsa XOR Kkem
   ```

Each secret keys **its own** HMAC, which is what makes the result a *split-key PRF*: if either key is a
uniformly random value an attacker does not hold, that branch's output is indistinguishable from random, and
XOR-ing the other branch into it — even a fully known other branch — leaves it indistinguishable from
random. So the data key is good unless **both** secrets are recovered.

Two details are load-bearing rather than decorative, and both are there for reasons worth knowing:

- **This is not an XOR of the two secrets.** XOR-ing the secrets together, or concatenating them into one
  key, would not give the property above. The XOR here is of two PRF *outputs*.
- **The two labels differ.** That is what stops the degenerate `rsaSecret == kemSecret`, where a single
  shared label would make the two branches identical and their XOR all zeros. A hostile *sender* can force
  it: it encapsulates first, sees `kemSecret`, and then chooses what to wrap under RSA.

`docs/format.md` §3.5.1 specifies the combiner normatively and §3.5.2 states the full rationale. You do not
need either to use the method.

## Supported parameter sets and key sizes

The ML-KEM half offers the same three parameter sets as [ML-KEM encryption](ml-kem.md), and the RSA half
takes any modulus size Enigma.Core will generate:

| Parameter set | NIST category | ML-KEM public key | ML-KEM private key | Header encapsulation |
|---------------|---------------|------------------:|-------------------:|---------------------:|
| `MLKemParameterSet.MLKem512` | 1 | 800 B | 1,632 B | 768 B |
| `MLKemParameterSet.MLKem768` | 3 | 1,184 B | 2,400 B | 1,088 B |
| `MLKemParameterSet.MLKem1024` | 5 | 1,568 B | 3,168 B | 1,568 B |

`EncryptAsync` defaults `parameterSet` to `MLKemParameterSet.MLKem1024` — the conservative choice, since a
container outlives the decision that made it. As with the ML-KEM method, note that **Enigma.Core's own
`CreateMLKemService` defaults to `MLKem768` instead**, so name the parameter set explicitly on both sides
and the mismatch cannot arise.

The header carries both variable-length fields, so a hybrid header is 42 + `N` + `M` bytes, where `N` is the
RSA modulus size and `M` the encapsulation length — 1,866 bytes for RSA-2048 with ML-KEM-1024. That is the
price of the method: roughly 1.8 KiB of header, once per container, regardless of payload size.

`DecryptAsync` takes **no** parameter set. The container records which one it was encapsulated under.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `IHybridDataEncryptionService` | `Enigma.DataEncryption` | The hybrid service. DI-friendly. |
| `HybridDataEncryptionService` | `Enigma.DataEncryption` | Concrete implementation. Create with `new` — the parameterless constructor wires Enigma.Core's default factories. |
| `MLKemParameterSet` | `Enigma.Core.Asymmetric.Pqc` | The ML-KEM parameter set: `MLKem512`, `MLKem768`, `MLKem1024`. |
| `Cipher` | `Enigma.DataEncryption` | Which 256-bit GCM cipher protects the payload: `Aes256Gcm`, `Twofish256Gcm`, `Serpent256Gcm`, `Camellia256Gcm`. |
| `DataEncryptionLimits` | `Enigma.DataEncryption` | Bounds the header's **two** length fields before either buffer is allocated, through `MaxWrappedKeyLength` and `MaxEncapsulationLength`. |
| `DataDecryptionException` | `Enigma.DataEncryption` | Either private key does not open this container, or the payload failed authentication. |
| `DataEncryptionFormatException` | `Enigma.DataEncryption` | The input is not a hybrid container, its parameter-set byte is undefined, or a length field is out of bounds. |
| `IPublicKeyService` | `Enigma.Core.Asymmetric.PublicKey` | Enigma.Core's RSA service — where RSA key pairs come from. |
| `IMLKemService` | `Enigma.Core.Asymmetric.Pqc` | Enigma.Core's ML-KEM service — where ML-KEM key pairs come from. |

The two methods:

```csharp
Task EncryptAsync(
    Stream input,
    Stream output,
    Cipher cipher,
    string rsaPublicKeyPem,
    byte[] mlKemPublicKey,
    MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);

Task DecryptAsync(
    Stream input,
    Stream output,
    string rsaPrivateKeyPem,
    byte[] mlKemPrivateKey,
    char[]? rsaKeyPassword = null,
    DataEncryptionLimits? limits = null,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

Neither disposes either stream, and both leave the streams wherever the operation ended. Caller-supplied
keys and passphrases are never mutated and never cleared. The service is stateless and safe for concurrent
use, so one instance can be shared across an application; it can equally be registered against
`IHybridDataEncryptionService` in a Microsoft.Extensions.DependencyInjection container (see
[Dependency injection](dependency-injection.md)).

## Usage

### Generate the two key pairs

Key generation belongs to Enigma.Core, and you need one pair from each primitive. RSA generation is the
slow part — seconds, against milliseconds for ML-KEM:

```csharp
using System;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;

IPublicKeyService rsa = new PublicKeyServiceFactory().CreatePublicKeyService();
(string rsaPublicKeyPem, string rsaPrivateKeyPem) = rsa.GenerateRsaKeyPair(3072);

IMLKemService kem = new MLKemServiceFactory()
    .CreateMLKemService(MLKemParameterSet.MLKem1024);
(byte[] mlKemPublicKey, byte[] mlKemPrivateKey) = kem.GenerateKeyPair();

Console.WriteLine($"ML-KEM public {mlKemPublicKey.Length} B, private {mlKemPrivateKey.Length} B");
```

**Keep the two halves together.** A hybrid container needs both private keys, so losing either one loses the
file — the same as losing both. Whatever you use to store credentials, store the pair as a unit.

### Encrypt and decrypt in memory

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption;

IPublicKeyService rsaService = new PublicKeyServiceFactory().CreatePublicKeyService();
(string rsaPublicKeyPem, string rsaPrivateKeyPem) = rsaService.GenerateRsaKeyPair(3072);

IMLKemService kem = new MLKemServiceFactory()
    .CreateMLKemService(MLKemParameterSet.MLKem1024);
(byte[] mlKemPublicKey, byte[] mlKemPrivateKey) = kem.GenerateKeyPair();

IHybridDataEncryptionService service = new HybridDataEncryptionService();

byte[] plaintext = Encoding.UTF8.GetBytes("Attack at dawn.");

using MemoryStream input = new(plaintext);
using MemoryStream container = new();

await service.EncryptAsync(
    input, container, Cipher.Aes256Gcm, rsaPublicKeyPem, mlKemPublicKey,
    MLKemParameterSet.MLKem1024);

// Rewind the container before reading it back.
container.Position = 0;

using MemoryStream recovered = new();
await service.DecryptAsync(container, recovered, rsaPrivateKeyPem, mlKemPrivateKey);

Console.WriteLine(Encoding.UTF8.GetString(recovered.ToArray()));  // Attack at dawn.
```

Note the asymmetry: the parameter set is named on encrypt and absent on decrypt, because by then it is in
the header.

### Encrypt a file, with an encrypted RSA private-key PEM

The RSA half accepts a passphrase-protected private-key PEM exactly as
[`IRsaDataEncryptionService`](rsa.md) does, through `rsaKeyPassword`. The file-path wrappers in
[File operations](file-operations.md) cover the hybrid too:

```csharp
using System;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption;

IHybridDataEncryptionService service = new HybridDataEncryptionService();

char[] keyPassword = "protect-the-rsa-key".ToCharArray();

try
{
    await service.DecryptFileAsync(
        "secret.bin",
        "secret.txt",
        rsaPrivateKeyPem: await System.IO.File.ReadAllTextAsync("recipient.rsa.enc.pem"),
        mlKemPrivateKey: await System.IO.File.ReadAllBytesAsync("recipient.mlkem.key.raw"),
        rsaKeyPassword: keyPassword);
}
finally
{
    Array.Clear(keyPassword, 0, keyPassword.Length);
}
```

The wrapper opens both files asynchronously, creates or overwrites the output, and **deletes the partial
output on any failure including cancellation** — so a wrong key never leaves a truncated plaintext on disk.

### Handle the failure modes

Both credentials are checked, but **they do not fail in the same place**, and the difference is worth
understanding because it is what the key-confirmation tag is for:

- A **wrong RSA private key** is caught by the OAEP unwrap. RSAES-OAEP detects a key that does not match,
  so this fails before the combiner runs.
- A **wrong ML-KEM private key** is caught by nothing at that stage. FIPS 203 *implicit rejection* means
  decapsulating with a wrong key **succeeds**, returning a wrong-but-well-formed 32-byte secret. The
  combined key is then wrong, and the header's **key-confirmation tag** is what turns that into a clean,
  immediate error — before a single payload byte is read.

Both surface as `DataDecryptionException`, so a caller who only needs "this did not open" writes one catch:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IHybridDataEncryptionService service = new HybridDataEncryptionService();
string rsaPrivateKeyPem = File.ReadAllText("recipient.rsa.pem");
byte[] mlKemPrivateKey = File.ReadAllBytes("recipient.mlkem.key.raw");

using FileStream container = File.OpenRead("secret.bin");
using MemoryStream recovered = new();

try
{
    await service.DecryptAsync(container, recovered, rsaPrivateKeyPem, mlKemPrivateKey);
}
catch (DataEncryptionFormatException ex)
{
    Console.WriteLine($"Not a hybrid container this library can read: {ex.Message}");
}
catch (DataDecryptionException ex)
{
    // Either key wrong, a malformed ML-KEM key, an undecryptable RSA PEM, or a tampered container.
    Console.WriteLine($"These keys do not open it: {ex.InnerException?.Message ?? ex.Message}");
}
```

**When both keys are wrong, the RSA failure is the one reported** — that half runs first. And on the
encrypt side the two halves differ again: an unusable RSA public-key PEM propagates from Enigma.Core as
`ArgumentException` or `FormatException`, while an unusable ML-KEM public key becomes an
`ArgumentException` on `mlKemPublicKey`.

> **One wrinkle about parameter names.** Because an unparseable PEM propagates unwrapped, the
> `ParamName` in that case is Enigma.Core's `publicKeyPem` / `privateKeyPem` rather than this method's
> `rsaPublicKeyPem` / `rsaPrivateKeyPem`. A `null` or empty PEM is rejected by this library and does carry
> the parameter's own name. Correcting the former would mean catching and re-throwing, which is exactly the
> wrapping the error mapping rules out for a credential-supply error.

### Bound both length fields

The hybrid header has **two** attacker-controlled lengths, and both are bounded before their buffers are
allocated. It introduces no cap of its own: they are an RSA wrapped secret and an ML-KEM encapsulation, so
`MaxWrappedKeyLength` and `MaxEncapsulationLength` apply, exactly as they do for methods `0x03` and `0x04`:

```csharp
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IHybridDataEncryptionService service = new HybridDataEncryptionService();

// This deployment only ever issues RSA-3072 keys and ML-KEM-1024 keys.
DataEncryptionLimits limits = new()
{
    MaxWrappedKeyLength = 384,
    MaxEncapsulationLength = 1_568,
};

using FileStream container = File.OpenRead("secret.bin");
using MemoryStream recovered = new();

await service.DecryptAsync(
    container, recovered, rsaPrivateKeyPem, mlKemPrivateKey, null, limits);
```

Passing `null` uses `DataEncryptionLimits.Default` (4,096 bytes for each). A length outside either bound
raises `DataEncryptionFormatException` before anything is allocated and before either private key is used.

### Progress and cancellation

Identical to every other method. Progress reports **increments of payload bytes processed** — the values sum
to the payload length, they are not a running total and not a percentage — and the header, both ciphertexts
included, is never counted:

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption;

IHybridDataEncryptionService service = new HybridDataEncryptionService();

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
    input, output, Cipher.Aes256Gcm, rsaPublicKeyPem, mlKemPublicKey,
    MLKemParameterSet.MLKem1024, progress, cts.Token);
```

Cancellation surfaces as `OperationCanceledException`.

## Notes

- **Use this method when the data outlives the primitives.** If a container might still need to be
  confidential after a quantum computer exists, or after a lattice break is published, one primitive is a
  bet and two are not. If neither concern applies, [RSA](rsa.md) or [ML-KEM](ml-kem.md) alone is smaller and
  simpler.
- **Both credentials are required in both directions.** Holding one of the two private keys is worth
  nothing. That is the point of the method, not an inconvenience of it.
- **This is post-quantum key establishment, not a post-quantum signature.** Anyone with the recipient's two
  public keys can produce a valid container, so a successful decrypt proves the container was made *for* you
  — not who made it.
- **The header costs about 1.8 KiB.** For RSA-2048 with ML-KEM-1024 it is 1,866 bytes, once per container.
  Choose a smaller ML-KEM parameter set if that matters more than the margin; the RSA modulus is the other
  lever.
- **Both public-key operations happen before anything is written**, so a key the library cannot use leaves
  the output stream untouched.
- **The container stream need not be seekable on decrypt.** The header is read forward exactly once and the
  payload is streamed from where it ended, so a network stream works.
- **A container from another method is a format error, not a misparse.** This service reads only method byte
  `0x05`. Note that a hybrid header and an ML-KEM header agree on their first 18 bytes but for that byte, so
  the method byte is doing real work — use [`IEncryptedDataInspector`](header-inspection.md) when you do not
  know which method produced a container.
