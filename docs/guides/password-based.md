# Password-based encryption — PBKDF2 & Argon2id

Enigma.DataEncryption encrypts data under a password through two services, one per key-derivation
function: `IPbkdf2DataEncryptionService` and `IArgon2DataEncryptionService`. You create the service
(directly with `new`, or resolve it from a container), hand it an input stream, an output stream, a
cipher and a password, and it writes a self-describing container — a plaintext header followed by the
AEAD payload.

The password never becomes the encryption key. Each call draws a fresh 16-byte salt, derives a 32-byte
data key from password + salt, and writes the salt and the cost parameters into the header, so the
reader needs nothing but the container and the password. The **complete header is passed as GCM
associated data**, so editing any byte of it — the iteration count included — turns decryption into an
authentication failure rather than a slower or weaker decryption.

Everything is stream-based and asynchronous, so encrypting a multi-gigabyte file uses the same constant
memory as encrypting a short string. The one exception is Argon2's memory cost, which is deliberately
large: that is the algorithm working, not the streaming leaking.

## Supported key-derivation functions

| KDF | Service | Notes |
|-----|---------|-------|
| Argon2id (v1.3) | `IArgon2DataEncryptionService` | **Recommended.** Memory-hard, so attack cost scales with memory as well as time. Prefer it for new work. |
| PBKDF2-HMAC-SHA256 | `IPbkdf2DataEncryptionService` | For interoperability and memory-constrained environments. Not memory-hard: a GPU attacks it far more cheaply than Argon2id at equivalent wall-clock cost. |

Both services expose the same four methods — `EncryptAsync` and `DecryptAsync`, each overloaded for a
`byte[]` and a `char[]` password — and differ only in their cost parameters.

**PBKDF2** takes one cost parameter, `iterations`, defaulting to
`DataEncryptionDefaults.Pbkdf2Iterations` (600,000 — the OWASP 2023 floor for PBKDF2-HMAC-SHA256).

**Argon2id** takes three, all named for what they cost:

| Parameter | Default (`DataEncryptionDefaults`) | Value | What it controls |
|-----------|-----------------------------------|-------|------------------|
| `iterations` | `Argon2Iterations` | 3 | Passes over memory — the time cost. |
| `memorySizeKb` | `Argon2MemorySizeKb` | 65,536 KiB (64 MiB) | The memory cost, **in kibibytes**. |
| `degreeOfParallelism` | `Argon2DegreeOfParallelism` | 4 | Parallel lanes. |

Those three together are RFC 9106's second recommended option. Raising `memorySizeKb` buys more than
raising `iterations` does, because memory is the expensive resource for an attacker; a reasonable way to
choose is to raise memory until a derivation takes as long as your slowest acceptable login, then leave
`iterations` at 3. Any of the four cost parameters at or below zero throws `ArgumentOutOfRangeException`
before any work starts.

The variant is always Argon2id at version 1.3, and the salt size (16 bytes), data-key size (32 bytes),
nonce size (12 bytes) and tag size (128 bits) are fixed invariants of the format — none of them is
selectable.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `IPbkdf2DataEncryptionService` | `Enigma.DataEncryption` | The PBKDF2 service. DI-friendly. |
| `Pbkdf2DataEncryptionService` | `Enigma.DataEncryption` | Concrete implementation. Create with `new` — the parameterless constructor wires Enigma.Core's default factories. |
| `IArgon2DataEncryptionService` | `Enigma.DataEncryption` | The Argon2id service. DI-friendly. |
| `Argon2DataEncryptionService` | `Enigma.DataEncryption` | Concrete implementation. Create with `new`. |
| `Cipher` | `Enigma.DataEncryption` | Which 256-bit GCM cipher protects the payload: `Aes256Gcm`, `Twofish256Gcm`, `Serpent256Gcm`, `Camellia256Gcm`. |
| `DataEncryptionDefaults` | `Enigma.DataEncryption` | The default cost parameters and the format's fixed sizes. |
| `DataEncryptionLimits` | `Enigma.DataEncryption` | Upper bounds applied to the cost fields **read from a header**. `DataEncryptionLimits.Default` is the shared instance. |
| `DataDecryptionException` | `Enigma.DataEncryption` | The password is wrong, or the payload failed authentication. |
| `DataEncryptionFormatException` | `Enigma.DataEncryption` | The input is not a container this service can parse, or a header field is out of bounds. |

Argon2's encrypt method is the widest of the four:

```csharp
Task EncryptAsync(
    Stream input,
    Stream output,
    Cipher cipher,
    char[] password,
    int iterations = DataEncryptionDefaults.Argon2Iterations,
    int memorySizeKb = DataEncryptionDefaults.Argon2MemorySizeKb,
    int degreeOfParallelism = DataEncryptionDefaults.Argon2DegreeOfParallelism,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

and its decrypt method is the narrowest, because every cost parameter comes back out of the header:

```csharp
Task DecryptAsync(
    Stream input,
    Stream output,
    char[] password,
    DataEncryptionLimits? limits = null,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

Neither method disposes either stream, and both leave the streams wherever the operation ended — the
caller owns stream lifetime. Both services are stateless and safe for concurrent use, so a single
instance can be shared across a whole application; `Pbkdf2DataEncryptionService` and
`Argon2DataEncryptionService` can equally be registered against their interfaces in a
Microsoft.Extensions.DependencyInjection container (see
[Dependency injection](dependency-injection.md)).

## Usage

### Encrypt and decrypt in memory

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();
byte[] plaintext = Encoding.UTF8.GetBytes("Attack at dawn.");

using MemoryStream input = new(plaintext);
using MemoryStream container = new();

await service.EncryptAsync(input, container, Cipher.Aes256Gcm, password);

// Rewind the container before reading it back.
container.Position = 0;

using MemoryStream recovered = new();
await service.DecryptAsync(container, recovered, password);

Console.WriteLine(Encoding.UTF8.GetString(recovered.ToArray()));  // Attack at dawn.
```

### Use PBKDF2 with a non-default iteration count

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IPbkdf2DataEncryptionService service = new Pbkdf2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();
byte[] plaintext = Encoding.UTF8.GetBytes("Attack at dawn.");

using MemoryStream input = new(plaintext);
using MemoryStream container = new();

await service.EncryptAsync(
    input, container, Cipher.Serpent256Gcm, password, iterations: 1_200_000);

Console.WriteLine($"{container.Length} bytes written");
```

The iteration count is written into the header, so `DecryptAsync` needs only the password — passing the
count again is neither possible nor necessary.

### Raise Argon2's cost above the defaults

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();
byte[] plaintext = Encoding.UTF8.GetBytes("Attack at dawn.");

using MemoryStream input = new(plaintext);
using MemoryStream container = new();

// 256 MiB of memory, 4 passes, 8 lanes — roughly 4× the default memory cost.
await service.EncryptAsync(
    input,
    container,
    Cipher.Aes256Gcm,
    password,
    iterations: 4,
    memorySizeKb: 262_144,
    degreeOfParallelism: 8);

Console.WriteLine($"{container.Length} bytes written");
```

### `byte[]` versus `char[]` passwords, and clearing them

Both services accept a password either way, and the choice is about who owns the encoding:

- **`char[]`** — the library UTF-8-encodes the characters into a temporary buffer and clears that buffer
  before returning. Use this unless you have a reason not to.
- **`byte[]`** — the bytes are used exactly as supplied. Use this when the password is already bytes, or
  when you need an encoding other than UTF-8.

In both cases **the caller's own array is never mutated and never cleared** — that is the caller's job,
because only the caller knows when the password is no longer needed:

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = Console.ReadLine()!.ToCharArray();

try
{
    byte[] plaintext = Encoding.UTF8.GetBytes("Attack at dawn.");

    using MemoryStream input = new(plaintext);
    using MemoryStream container = new();

    await service.EncryptAsync(input, container, Cipher.Aes256Gcm, password);
}
finally
{
    // The library cleared its own derived key material; this array is yours.
    Array.Clear(password, 0, password.Length);
}
```

The data key and the key-confirmation key the library derives internally are always cleared before the
method returns, whether it succeeded or threw.

### Reject a hostile header before it costs anything

The cost parameters in a container's header are attacker-controlled: nothing stops someone handing you a
container claiming a 1 GiB Argon2 memory cost. `DataEncryptionLimits` bounds every such field **before
any memory is allocated or any derivation work is done**, and a field that is out of bounds raises
`DataEncryptionFormatException`.

Passing `null` uses `DataEncryptionLimits.Default`, whose bounds say what is *survivable* rather than
what is *sensible*. Tighten them to your own policy:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

DataEncryptionLimits limits = new()
{
    MaxArgon2Iterations = 8,
    MaxArgon2MemorySizeKb = 262_144,      // 256 MiB — refuse anything greedier
    MaxArgon2DegreeOfParallelism = 8,
};

char[] password = "correct horse battery staple".ToCharArray();

using FileStream container = File.OpenRead("secret.bin");
using MemoryStream recovered = new();

try
{
    await service.DecryptAsync(container, recovered, password, limits);
}
catch (DataEncryptionFormatException ex)
{
    Console.WriteLine($"Refused: {ex.Message}");
}
catch (DataDecryptionException)
{
    Console.WriteLine("Wrong password.");
}
```

Catching the two exception types separately is what tells a wrong password apart from a container this
service will not process. Both derive from `DataEncryptionException`, so catch that instead when the
distinction does not matter.

### Progress and cancellation

Every operation takes an optional `IProgress<int>` and a `CancellationToken`. Progress reports
**increments of payload bytes processed** — the values sum to the payload length, they are not a running
total and not a percentage — and header bytes are never counted. It earns its keep on large files, where
the KDF cost is a fixed prelude and the payload is what takes the time.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();

using FileStream input = File.OpenRead("large-input.bin");
using FileStream output = File.Create("large-input.bin.enc");

long total = input.Length;
long done = 0;
var progress = new Progress<int>(bytes =>
{
    done += bytes;
    Console.WriteLine($"{done * 100 / total}%");
});

using CancellationTokenSource cts = new(TimeSpan.FromMinutes(10));

await service.EncryptAsync(
    input, output, Cipher.Aes256Gcm, password, progress: progress, cancellationToken: cts.Token);
```

Cancellation surfaces as `OperationCanceledException`. The output stream is left with whatever had been
written when the token fired — for file-to-file work, prefer the extension methods in
[File operations](file-operations.md), which delete the partial output for you.

## Notes

- **Prefer Argon2id.** PBKDF2 is here for interoperability and for environments where 64 MiB of
  derivation memory is not available. At equal wall-clock cost, Argon2id is the harder target.
- **Argon2 memory is recorded in kibibytes**, not as a power-of-two exponent. Readers of
  `Enigma.Cryptography.DataEncryption`'s format should note the change: this is a different format, not
  a compatible revision of that one.
- **Wrong-password detection is fast and happens before any payload byte is read.** A key-confirmation
  tag in the header is verified in constant time immediately after derivation, so a wrong password costs
  one derivation and no payload work — and, unlike plain GCM, the construction is key-committing.
- **The input stream is read to its end** from wherever it is positioned. Position it at the start of
  the data before calling, and rewind a `MemoryStream` you have just written before decrypting it.
- **The container stream need not be seekable on decrypt.** The header is read forward exactly once and
  the payload is streamed from where it ended, so a network stream works.
- **Handing a container to the wrong service is a format error, not a misparse.** Each service reads
  only its own method byte; a PBKDF2 container passed to `IArgon2DataEncryptionService` raises
  `DataEncryptionFormatException`. Use [`IEncryptedDataInspector`](header-inspection.md) when you do not
  know which method produced a container.
- **The cost parameters do not change the output size**, only the time and memory spent deriving the
  key. Container size is 53 bytes of header for PBKDF2, 61 for Argon2, plus the payload and its 16-byte
  GCM tag.
