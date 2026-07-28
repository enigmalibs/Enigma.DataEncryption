# File operations

`DataEncryptionFileExtensions` provides file-path wrappers over the stream-based services: fourteen
extension methods that open the two files, run the operation, and clean up after a failure. You call them
on any of the five encryption service interfaces — `service.EncryptFileAsync(inputPath, outputPath, …)` —
and they delegate to the same `EncryptAsync` / `DecryptAsync` you would have called yourself.

There is no new cryptography here and no new behaviour beyond file handling. Argument validation, credential
handling, progress semantics and every exception are exactly those of the underlying stream overload; the
wrappers add file opening, and the three semantics below.

Because they are extension methods on the **interfaces** rather than members of the implementations, they
compose with any implementation — including a test double.

## Supported operations

Fourteen methods: four per password method (encrypt and decrypt, each with a `byte[]` and a `char[]`
password overload), and two each for RSA, ML-KEM and the hybrid.

| Service interface | Method | Credential parameter |
|-------------------|--------|----------------------|
| `IPbkdf2DataEncryptionService` | `EncryptFileAsync` | `byte[] password` |
| `IPbkdf2DataEncryptionService` | `EncryptFileAsync` | `char[] password` |
| `IPbkdf2DataEncryptionService` | `DecryptFileAsync` | `byte[] password` |
| `IPbkdf2DataEncryptionService` | `DecryptFileAsync` | `char[] password` |
| `IArgon2DataEncryptionService` | `EncryptFileAsync` | `byte[] password` |
| `IArgon2DataEncryptionService` | `EncryptFileAsync` | `char[] password` |
| `IArgon2DataEncryptionService` | `DecryptFileAsync` | `byte[] password` |
| `IArgon2DataEncryptionService` | `DecryptFileAsync` | `char[] password` |
| `IRsaDataEncryptionService` | `EncryptFileAsync` | `string publicKeyPem` |
| `IRsaDataEncryptionService` | `DecryptFileAsync` | `string privateKeyPem`, optional `char[]? keyPassword` |
| `IMLKemDataEncryptionService` | `EncryptFileAsync` | `byte[] publicKey`, optional `MLKemParameterSet parameterSet` |
| `IMLKemDataEncryptionService` | `DecryptFileAsync` | `byte[] privateKey` |
| `IHybridDataEncryptionService` | `EncryptFileAsync` | `string rsaPublicKeyPem` **and** `byte[] mlKemPublicKey`, optional `MLKemParameterSet parameterSet` |
| `IHybridDataEncryptionService` | `DecryptFileAsync` | `string rsaPrivateKeyPem` **and** `byte[] mlKemPrivateKey`, optional `char[]? rsaKeyPassword` |

Each carries the same optional parameters as its stream counterpart — the cost parameters on encrypt, the
`DataEncryptionLimits? limits` on decrypt, and `IProgress<int>? progress` plus `CancellationToken` on both.

### The three semantics

Every one of the fourteen shares these, and all three are load-bearing rather than incidental:

1. **Input** is opened `FileMode.Open`, `FileAccess.Read`, `FileShare.Read`, with a 4,096-byte buffer and
   `useAsync: true`. `FileShare.Read` means other readers may hold the file open concurrently, so you can
   encrypt a file something else is reading.

2. **Output** is opened `FileMode.Create` — **create-or-overwrite**. An existing file at `outputPath` is
   **truncated without warning**. Access is `FileAccess.Write`, `FileShare.None`, 4,096-byte buffer,
   `useAsync: true`. Check for an existing file yourself if overwriting is not what you want.

3. **On any failure — including cancellation — the partial output file is deleted** before the exception
   propagates. A failed decrypt therefore never leaves a truncated plaintext on disk, and a wrong password
   leaves nothing behind. The delete is best-effort: if it fails (a locked or read-only file), that
   failure is swallowed rather than allowed to mask the original exception.

Two consequences of how that cleanup is implemented are worth knowing:

- **Arguments are validated before either file is opened.** Since the output is `FileMode.Create`,
  validating afterwards would truncate a caller's existing file only to delete it again — so a bad
  argument leaves the filesystem completely untouched, and the create-then-delete cycle is reserved for
  failures that genuinely required the attempt.
- **The output handle is closed before the cleanup delete runs**, because deleting a file the process
  still holds open fails on Windows. The ordering is what makes the cleanup actually work rather than
  merely be attempted.

A failure *opening the input* — a missing file, say — happens before any output exists, and is the one case
that deletes nothing.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `DataEncryptionFileExtensions` | `Enigma.DataEncryption` | The static class holding all fourteen methods. You never name it — the methods appear on the service interfaces. |
| `IPbkdf2DataEncryptionService`, `IArgon2DataEncryptionService`, `IRsaDataEncryptionService`, `IMLKemDataEncryptionService` | `Enigma.DataEncryption` | The receivers. Any implementation works. |
| `Cipher` | `Enigma.DataEncryption` | Which 256-bit GCM cipher protects the payload. |
| `DataEncryptionDefaults` | `Enigma.DataEncryption` | The default cost parameters, unchanged from the stream overloads. |
| `DataEncryptionLimits` | `Enigma.DataEncryption` | Header bounds on decrypt. |
| `DataDecryptionException` / `DataEncryptionFormatException` | `Enigma.DataEncryption` | The same two container failures as the stream API. |
| `IOException` | `System.IO` | A file could not be opened, read or written. |

A representative pair:

```csharp
public static Task EncryptFileAsync(
    this IArgon2DataEncryptionService service,
    string inputPath,
    string outputPath,
    Cipher cipher,
    char[] password,
    int iterations = DataEncryptionDefaults.Argon2Iterations,
    int memorySizeKb = DataEncryptionDefaults.Argon2MemorySizeKb,
    int degreeOfParallelism = DataEncryptionDefaults.Argon2DegreeOfParallelism,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);

public static Task DecryptFileAsync(
    this IArgon2DataEncryptionService service,
    string inputPath,
    string outputPath,
    char[] password,
    DataEncryptionLimits? limits = null,
    IProgress<int>? progress = null,
    CancellationToken cancellationToken = default);
```

Both live in `Enigma.DataEncryption`, the same namespace as the interfaces, so a single `using
Enigma.DataEncryption;` brings the extension methods into scope alongside the types.

## Usage

### Encrypt and decrypt a file with a password

```csharp
using System;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();

try
{
    await service.EncryptFileAsync(
        "report.pdf", "report.pdf.enc", Cipher.Aes256Gcm, password);

    await service.DecryptFileAsync(
        "report.pdf.enc", "report-recovered.pdf", password);

    Console.WriteLine("Round-tripped.");
}
finally
{
    Array.Clear(password, 0, password.Length);
}
```

No streams to open, position or dispose — and if either call fails, its output file is gone rather than
left half-written.

### Encrypt a file for an RSA recipient

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IRsaDataEncryptionService service = new RsaDataEncryptionService();

string publicKeyPem = File.ReadAllText("recipient.pub");
await service.EncryptFileAsync(
    "report.pdf", "report.pdf.enc", Cipher.Aes256Gcm, publicKeyPem);

// And on the recipient's side, with an encrypted private-key PEM:
string privateKeyPem = File.ReadAllText("recipient.key");
char[] pemPassphrase = "protect-the-key-file".ToCharArray();

try
{
    await service.DecryptFileAsync(
        "report.pdf.enc", "report-recovered.pdf", privateKeyPem, keyPassword: pemPassphrase);
}
finally
{
    Array.Clear(pemPassphrase, 0, pemPassphrase.Length);
}

Console.WriteLine("Done.");
```

### Encrypt a file for an ML-KEM recipient

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption;

IMLKemDataEncryptionService service = new MLKemDataEncryptionService();

byte[] publicKey = File.ReadAllBytes("recipient.mlkem.pub");

await service.EncryptFileAsync(
    "report.pdf",
    "report.pdf.enc",
    Cipher.Aes256Gcm,
    publicKey,
    MLKemParameterSet.MLKem1024);

Console.WriteLine("Encrypted.");
```

As with the stream API, `DecryptFileAsync` takes no parameter set — the container records it.

### Tune the cost, and tighten the limits

Every optional parameter of the stream overloads is here too, so the file wrappers are not a reduced
surface:

```csharp
using System;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();

try
{
    await service.EncryptFileAsync(
        "report.pdf",
        "report.pdf.enc",
        Cipher.Serpent256Gcm,
        password,
        iterations: 4,
        memorySizeKb: 262_144,
        degreeOfParallelism: 8);

    // Refuse containers greedier than this deployment's own policy.
    DataEncryptionLimits limits = new()
    {
        MaxArgon2Iterations = 8,
        MaxArgon2MemorySizeKb = 262_144,
        MaxArgon2DegreeOfParallelism = 8,
    };

    await service.DecryptFileAsync(
        "report.pdf.enc", "report-recovered.pdf", password, limits);
}
finally
{
    Array.Clear(password, 0, password.Length);
}
```

### Report progress as a percentage

Progress reports **increments of payload bytes processed** — the values sum to the payload length, they
are not a running total and not a percentage — and header bytes are never counted. With a file you know
the total up front, so a percentage is a couple of lines:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();

long total = new FileInfo("large-input.bin").Length;
long done = 0;
var progress = new Progress<int>(bytes =>
{
    done += bytes;
    Console.Write($"\r{done * 100 / total}%");
});

try
{
    await service.EncryptFileAsync(
        "large-input.bin", "large-input.bin.enc", Cipher.Aes256Gcm, password,
        progress: progress);

    Console.WriteLine();
}
finally
{
    Array.Clear(password, 0, password.Length);
}
```

On **encrypt** the payload byte count equals the input file's length. On **decrypt** it equals the output's
— the container is longer than its payload by the header and the 16-byte GCM tag, so use
`containerLength - header.HeaderLength - 16` if you want an exact denominator (see
[Header inspection](header-inspection.md)).

### Cancel cleanly

Cancellation is where the delete-on-failure semantics earn their keep: the partial output is removed
before `OperationCanceledException` reaches you, so there is nothing to clean up by hand.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();
using CancellationTokenSource cts = new(TimeSpan.FromSeconds(30));

try
{
    await service.EncryptFileAsync(
        "large-input.bin", "large-input.bin.enc", Cipher.Aes256Gcm, password,
        cancellationToken: cts.Token);
}
catch (OperationCanceledException)
{
    bool leftBehind = File.Exists("large-input.bin.enc");
    Console.WriteLine($"Cancelled. Partial output exists: {leftBehind}");  // False
}
finally
{
    Array.Clear(password, 0, password.Length);
}
```

### Handle the failure modes

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IArgon2DataEncryptionService service = new Argon2DataEncryptionService();

char[] password = "correct horse battery staple".ToCharArray();

try
{
    await service.DecryptFileAsync("secret.bin", "secret.txt", password);
}
catch (FileNotFoundException)
{
    Console.WriteLine("No such container. Nothing was written.");
}
catch (DataEncryptionFormatException ex)
{
    Console.WriteLine($"Not an Argon2 container: {ex.Message}");
}
catch (DataDecryptionException)
{
    Console.WriteLine("Wrong password.");
}
catch (IOException ex)
{
    Console.WriteLine($"File error: {ex.Message}");
}
finally
{
    Array.Clear(password, 0, password.Length);
}
```

In every case but the first, `secret.txt` has already been deleted by the time the exception reaches you.
`FileNotFoundException` derives from `IOException`, so order those catch clauses most-specific first as
above.

## Notes

- **The output file is overwritten without warning.** `FileMode.Create` truncates an existing file. If
  that is not what you want, check `File.Exists(outputPath)` before calling — the wrappers deliberately
  do not, because "overwrite" is the right default for a tool that writes derived files.
- **Deleting the partial output is best-effort.** If the delete itself fails, the original exception is
  what propagates — replacing it with "could not delete the partial output" would hide the real failure.
  Only `IOException` and `UnauthorizedAccessException` from the delete are swallowed.
- **A bad argument touches nothing on disk.** Null or empty paths, an empty password, an undefined
  `Cipher` or a non-positive cost parameter all throw before either file is opened.
- **Credential handling is identical to the stream API.** Caller-supplied arrays are never mutated and
  never cleared; `char[]` passwords are UTF-8-encoded into a temporary buffer the library clears itself.
  Clearing your own array is your job, as every snippet above does.
- **Both files are opened with `useAsync: true`**, so these are genuinely asynchronous file operations
  rather than blocking work on a thread-pool thread.
- **They are extension methods, so they compose with a test double.** A fake
  `IArgon2DataEncryptionService` gets the file wrappers for free — which is also why the wrappers
  validate their own arguments rather than trusting the receiver to.
- **For anything other than plain file-to-file work, use the stream API directly** — the wrappers exist
  for the common case, not to replace it. See [Password-based encryption](password-based.md),
  [RSA](rsa.md) and [ML-KEM](ml-kem.md).
