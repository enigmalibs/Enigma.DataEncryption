# Header inspection

Enigma.DataEncryption lets you read a container's header **without decrypting it and without any
credential**, through `IEncryptedDataInspector`. You create the inspector (directly with `new`, or resolve
it from a container), hand it a stream positioned at the start of a container, and get back an
`EncryptedDataHeader` describing what the container is.

This answers the questions a caller has *before* it can even ask for a credential: which method produced
this container, which cipher protects it, how costly the key derivation will be, and where the payload
starts. Every container this library writes is self-describing precisely so that this is possible — the
header is plaintext by design, and reading it needs no secret.

Nothing secret comes back. `EncryptedDataHeader` deliberately omits the salt, the GCM nonce, the wrapped
key, the ML-KEM encapsulation and the key-confirmation tag: exposing them would serve no caller purpose.
What is there is what a caller can act on.

## Supported operations

| Operation | Method | Credential | Notes |
|-----------|--------|------------|-------|
| Read a header | `ReadHeaderAsync` | **none** | Validates the magic, method, version and every cost/length field. Reads no payload byte, so it cannot fail with `DataDecryptionException`. |

`ReadHeaderAsync` applies exactly the same `DataEncryptionLimits` bounds that decryption would, so a
header the inspector accepts is a header the matching service will not reject on those grounds. Passing
`null` uses `DataEncryptionLimits.Default`; a field out of bounds raises `DataEncryptionFormatException`,
as does a bad magic, an unknown method byte, a format version other than `0x10`, or a stream that ends
inside the header.

**Stream position is the one behaviour to plan around.** Reading a header consumes it, so:

- **If the stream is seekable, the original position is restored before returning** — you can hand the
  same stream straight to a decryption service.
- **If it is not seekable, the stream is left positioned at the first payload byte** and the header cannot
  be re-read. A caller that needs both the header and a subsequent decrypt must buffer the stream itself.

The stream is never disposed either way.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `IEncryptedDataInspector` | `Enigma.DataEncryption` | The inspector. DI-friendly. |
| `EncryptedDataInspector` | `Enigma.DataEncryption` | Concrete implementation. Create with `new` — it has no dependencies. |
| `EncryptedDataHeader` | `Enigma.DataEncryption` | The parsed header. A `sealed record`, so it compares and prints by value. |
| `EncryptionMethod` | `Enigma.DataEncryption` | Which method produced the container: `Pbkdf2`, `Argon2`, `Rsa`, `MLKem`. |
| `Cipher` | `Enigma.DataEncryption` | Which 256-bit GCM cipher protects the payload: `Aes256Gcm`, `Twofish256Gcm`, `Serpent256Gcm`, `Camellia256Gcm`. |
| `DataEncryptionLimits` | `Enigma.DataEncryption` | The bounds applied while parsing. `DataEncryptionLimits.Default` is the shared instance. |
| `DataEncryptionFormatException` | `Enigma.DataEncryption` | The input is not a container this library can parse, or a field is out of bounds. |

The one method:

```csharp
Task<EncryptedDataHeader> ReadHeaderAsync(
    Stream input,
    DataEncryptionLimits? limits = null,
    CancellationToken cancellationToken = default);
```

### What `EncryptedDataHeader` carries

Four properties are present on every container:

| Property | Type | Meaning |
|----------|------|---------|
| `Method` | `EncryptionMethod` | Which credential is required, and therefore which service can decrypt it. |
| `FormatVersion` | `byte` | Always `DataEncryptionDefaults.FormatVersion` (`0x10`) — any other value is rejected while parsing. |
| `Cipher` | `Cipher` | The AEAD block cipher protecting the payload. |
| `HeaderLength` | `int` | The total header length — equivalently, **the offset of the first payload byte**. |

The rest are method-specific and are `null` when they do not apply:

| Property | Type | Populated when `Method` is |
|----------|------|---------------------------|
| `Pbkdf2Iterations` | `int?` | `Pbkdf2` |
| `Argon2Iterations` | `int?` | `Argon2` |
| `Argon2MemorySizeKb` | `int?` | `Argon2` |
| `Argon2DegreeOfParallelism` | `int?` | `Argon2` |
| `WrappedKeyLength` | `int?` | `Rsa` — equals the RSA modulus size in bytes |
| `EncapsulationLength` | `int?` | `MLKem` |
| `MLKemParameterSet` | `MLKemParameterSet?` | `MLKem` (the enum is Enigma.Core's, in `Enigma.Core.Asymmetric.Pqc`) |

`HeaderLength` is 53 for PBKDF2, 61 for Argon2, `37 + WrappedKeyLength` for RSA and
`38 + EncapsulationLength` for ML-KEM — so it is also how you compute the payload size of a container
whose total length you know.

The inspector is stateless and safe for concurrent use, so one instance can be shared across an
application; `EncryptedDataInspector` can equally be registered against `IEncryptedDataInspector` in a
Microsoft.Extensions.DependencyInjection container (see [Dependency injection](dependency-injection.md)).

## Usage

### Report what a container is

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IEncryptedDataInspector inspector = new EncryptedDataInspector();

using FileStream container = File.OpenRead("secret.bin");
EncryptedDataHeader header = await inspector.ReadHeaderAsync(container);

Console.WriteLine($"Method:  {header.Method}");
Console.WriteLine($"Cipher:  {header.Cipher}");
Console.WriteLine($"Version: 0x{header.FormatVersion:X2}");
Console.WriteLine($"Payload starts at byte {header.HeaderLength}");
Console.WriteLine($"Payload is {container.Length - header.HeaderLength} bytes (tag included)");

switch (header.Method)
{
    case EncryptionMethod.Pbkdf2:
        Console.WriteLine($"PBKDF2, {header.Pbkdf2Iterations} iterations");
        break;
    case EncryptionMethod.Argon2:
        Console.WriteLine(
            $"Argon2id, {header.Argon2Iterations} passes over " +
            $"{header.Argon2MemorySizeKb} KiB across {header.Argon2DegreeOfParallelism} lanes");
        break;
    case EncryptionMethod.Rsa:
        Console.WriteLine($"RSA, {header.WrappedKeyLength * 8}-bit modulus");
        break;
    case EncryptionMethod.MLKem:
        Console.WriteLine($"ML-KEM {header.MLKemParameterSet}, {header.EncapsulationLength}-byte encapsulation");
        break;
    case EncryptionMethod.Hybrid:
        // The one method that populates both length fields and the parameter set.
        Console.WriteLine(
            $"Hybrid: RSA {header.WrappedKeyLength * 8}-bit modulus + ML-KEM {header.MLKemParameterSet}, " +
            $"{header.EncapsulationLength}-byte encapsulation");
        break;
}
```

Reading `container.Length` after the call works because a `FileStream` is seekable, so the inspector
restored the position — the stream is exactly as you left it.

### Detect, then dispatch

The pattern this API exists for: inspect first, prompt for the right credential, then decrypt with the
matching service. On a seekable stream the same handle is reusable, so there is nothing to rewind.

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IEncryptedDataInspector inspector = new EncryptedDataInspector();

using FileStream container = File.OpenRead("secret.bin");
using FileStream output = File.Create("secret.out");

EncryptedDataHeader header = await inspector.ReadHeaderAsync(container);

// The inspector restored the position, so `container` is back at the magic.
switch (header.Method)
{
    case EncryptionMethod.Pbkdf2:
    {
        char[] password = PromptForPassword();
        await new Pbkdf2DataEncryptionService()
            .DecryptAsync(container, output, password);
        break;
    }

    case EncryptionMethod.Argon2:
    {
        char[] password = PromptForPassword();
        await new Argon2DataEncryptionService()
            .DecryptAsync(container, output, password);
        break;
    }

    case EncryptionMethod.Rsa:
    {
        string privateKeyPem = File.ReadAllText("recipient.key");
        await new RsaDataEncryptionService()
            .DecryptAsync(container, output, privateKeyPem);
        break;
    }

    case EncryptionMethod.MLKem:
    {
        byte[] privateKey = File.ReadAllBytes("recipient.mlkem.key.raw");
        await new MLKemDataEncryptionService()
            .DecryptAsync(container, output, privateKey);
        break;
    }

    case EncryptionMethod.Hybrid:
    {
        // Two credentials, both required — see the hybrid guide.
        string privateKeyPem = File.ReadAllText("recipient.key");
        byte[] mlKemPrivateKey = File.ReadAllBytes("recipient.mlkem.key.raw");
        await new HybridDataEncryptionService()
            .DecryptAsync(container, output, privateKeyPem, mlKemPrivateKey);
        break;
    }

    default:
        throw new InvalidOperationException($"Unhandled method {header.Method}.");
}

static char[] PromptForPassword()
{
    Console.Write("Password: ");
    return Console.ReadLine()!.ToCharArray();
}
```

The `default` arm is unreachable for a container this library parsed — `ReadHeaderAsync` rejects any
method byte outside the five — but it keeps the switch honest if a future format version adds one.

### Gate on cost before spending it

Argon2's memory cost is attacker-controlled and paid *before* a wrong password can be detected. Inspecting
first lets you refuse a greedy container without allocating for it, and lets you warn a user before a
derivation that will take noticeable time:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IEncryptedDataInspector inspector = new EncryptedDataInspector();

using FileStream container = File.OpenRead("secret.bin");
EncryptedDataHeader header = await inspector.ReadHeaderAsync(container);

if (header.Method == EncryptionMethod.Argon2 && header.Argon2MemorySizeKb > 262_144)
{
    Console.WriteLine(
        $"This container asks for {header.Argon2MemorySizeKb / 1024} MiB of derivation memory. " +
        "Refusing to open it.");
    return;
}

Console.WriteLine("Cost is acceptable — go ahead and prompt for the password.");
```

For a hard policy rather than a warning, pass the same bound as `DataEncryptionLimits` to both the
inspector and the decrypt call, and let `DataEncryptionFormatException` do the refusing:

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IEncryptedDataInspector inspector = new EncryptedDataInspector();

DataEncryptionLimits limits = new()
{
    MaxArgon2MemorySizeKb = 262_144,   // 256 MiB
    MaxPbkdf2Iterations = 2_000_000,
};

using FileStream container = File.OpenRead("secret.bin");

try
{
    EncryptedDataHeader header = await inspector.ReadHeaderAsync(container, limits);
    Console.WriteLine($"Acceptable: {header.Method} / {header.Cipher}");
}
catch (DataEncryptionFormatException ex)
{
    Console.WriteLine($"Refused: {ex.Message}");
}
```

### Inspect a non-seekable stream

On a non-seekable stream the header cannot be restored, so the inspector leaves the stream at the first
payload byte. If you only want to *report* on the container, that is fine. If you also intend to decrypt
it, buffer the stream first and inspect the buffer:

```csharp
using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IEncryptedDataInspector inspector = new EncryptedDataInspector();

using HttpClient http = new();
using Stream network = await http.GetStreamAsync("https://example.invalid/secret.bin");

// A network stream is forward-only: buffer it so the header can be read twice.
using MemoryStream buffered = new();
await network.CopyToAsync(buffered);
buffered.Position = 0;

EncryptedDataHeader header = await inspector.ReadHeaderAsync(buffered);
Console.WriteLine($"{header.Method} container, payload at byte {header.HeaderLength}");

// `buffered` is seekable, so it is back at the magic and ready to decrypt.
```

If buffering the whole container is not acceptable — a large download, say — the alternative is to skip
the inspector and go straight to the decryption service, which reads the header forward exactly once and
needs no seeking. You give up detect-then-dispatch, but each service reports a container of the wrong
method as `DataEncryptionFormatException`, so trying the one you expect is still a safe operation.

### Cancellation

`ReadHeaderAsync` takes a `CancellationToken`. There is no `IProgress<int>` overload, because a header is
at most a couple of kilobytes — there is nothing to report progress against.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption;

IEncryptedDataInspector inspector = new EncryptedDataInspector();

using CancellationTokenSource cts = new(TimeSpan.FromSeconds(5));
using FileStream container = File.OpenRead("secret.bin");

EncryptedDataHeader header =
    await inspector.ReadHeaderAsync(container, limits: null, cancellationToken: cts.Token);

Console.WriteLine(header.Method);
```

Cancellation surfaces as `OperationCanceledException`.

## Notes

- **The inspector cannot report a wrong credential**, because it uses none and reads no payload byte. It
  raises `DataEncryptionFormatException` or nothing; `DataDecryptionException` is not among its outcomes.
- **A header the inspector accepts is not a container that will decrypt.** It proves the container is
  well-formed and within your limits — not that you hold the key. That is what the key-confirmation tag,
  checked during decryption, is for.
- **Everything the header exposes is already plaintext on the wire**, so inspecting a container reveals
  nothing to you that an attacker with the file did not already have. What the header *omits* — salt,
  nonce, wrapped key, encapsulation, confirmation tag — is omitted because callers have no use for it,
  not because it is secret.
- **The header is authenticated even though it is plaintext.** The complete header is passed to GCM as
  associated data, so a container whose header has been edited — a lowered iteration count, a swapped
  cipher byte — will inspect cleanly and then fail authentication on decrypt.
- **`EncryptedDataHeader` is a record**, so two headers with equal values are equal, and `ToString()`
  prints every property. That makes it convenient in tests and log lines.
- **Position the stream at the magic before calling.** The inspector reads from wherever the stream is,
  not from byte zero.
- **The normative field-by-field definition is [`../format.md`](../format.md)** — this guide covers the
  API, not the wire format.
