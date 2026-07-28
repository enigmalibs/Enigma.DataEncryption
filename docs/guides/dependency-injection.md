# Dependency injection

Enigma.DataEncryption registers with a Microsoft.Extensions.DependencyInjection container through one
call: `services.AddEnigmaDataEncryption()`. It registers the four encryption services, the inspector, and
the Enigma.Core factories they depend on — all as singletons, all with `TryAdd` — and returns the same
collection for chaining.

The extension lives in the `Microsoft.Extensions.DependencyInjection` namespace rather than
`Enigma.DataEncryption`, following the convention every `Microsoft.Extensions.*` registration extension
follows: `AddEnigmaDataEncryption()` is discoverable on `IServiceCollection` without an extra `using`.

Nothing about the library *requires* a container. Every service has a public parameterless constructor, so
`new Argon2DataEncryptionService()` is a complete, correct instance — the DI registration is a
convenience for applications already using a container, not a dependency.

## Supported operations

| Operation | Method | Notes |
|-----------|--------|-------|
| Register everything | `AddEnigmaDataEncryption()` | Idempotent. Calling it twice is harmless, and it never replaces a registration you made yourself. |

There is one method and it takes no options. There is nothing to configure at registration time because
the services are stateless: every choice — cipher, cost parameters, limits — is made per call, not per
instance.

### What gets registered

**This library's services**, each against its interface:

| Service interface | Implementation | Lifetime |
|-------------------|----------------|----------|
| `IPbkdf2DataEncryptionService` | `Pbkdf2DataEncryptionService` | Singleton |
| `IArgon2DataEncryptionService` | `Argon2DataEncryptionService` | Singleton |
| `IRsaDataEncryptionService` | `RsaDataEncryptionService` | Singleton |
| `IMLKemDataEncryptionService` | `MLKemDataEncryptionService` | Singleton |
| `IEncryptedDataInspector` | `EncryptedDataInspector` | Singleton |

**Enigma.Core's factories**, which those services consume. Enigma.Core deliberately ships no
`AddEnigmaCore`, so registering them is this method's responsibility:

| Factory interface | Implementation | Namespace |
|-------------------|----------------|-----------|
| `IBlockCipherServiceFactory` | `BlockCipherServiceFactory` | `Enigma.Core.Symmetric.BlockCiphers` |
| `IPbkdf2ServiceFactory` | `Pbkdf2ServiceFactory` | `Enigma.Core.KeyDerivation` |
| `IArgon2ServiceFactory` | `Argon2ServiceFactory` | `Enigma.Core.KeyDerivation` |
| `IPublicKeyServiceFactory` | `PublicKeyServiceFactory` | `Enigma.Core.Asymmetric.PublicKey` |
| `IMLKemServiceFactory` | `MLKemServiceFactory` | `Enigma.Core.Asymmetric.Pqc` |
| `IHmacServiceFactory` | `HmacServiceFactory` | `Enigma.Core.Hashing.Hmac` |

**Singleton is correct** because every one of these services is stateless and thread-safe: all
per-operation state — keys, nonces, buffers — lives on the stack of the call. There is no shared mutable
field to contend over, so a single instance serves every concurrent request in a web application without
synchronisation.

**Every registration uses `TryAdd`**, so a consumer who has already registered their own implementation of
any of these keeps it. Register a custom `IBlockCipherServiceFactory` first and
`AddEnigmaDataEncryption()` will build the four services on top of yours.

## Key types

| Type | Namespace | Role |
|------|-----------|------|
| `ServiceCollectionExtensions` | `Microsoft.Extensions.DependencyInjection` | The static class holding `AddEnigmaDataEncryption()`. You never name it. |
| `IServiceCollection` | `Microsoft.Extensions.DependencyInjection` | The receiver, from `Microsoft.Extensions.DependencyInjection.Abstractions`. |
| The five service interfaces | `Enigma.DataEncryption` | What you inject. |
| The five implementations | `Enigma.DataEncryption` | What is registered — each has a public parameterless constructor and a public constructor taking Enigma.Core factories. |

```csharp
public static IServiceCollection AddEnigmaDataEncryption(this IServiceCollection services);
```

It throws `ArgumentNullException` if `services` is `null`, and nothing else.

**About packages.** The library depends on **`Microsoft.Extensions.DependencyInjection.Abstractions`**
alone — enough to define the extension method against `IServiceCollection`. Building an actual container
needs the concrete **`Microsoft.Extensions.DependencyInjection`** package (or one of the hosting packages
that brings it in), which is a reference your application adds, not one the library forces on you.

## Usage

### Register and resolve

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncryption;
using Microsoft.Extensions.DependencyInjection;

ServiceCollection services = new();
services.AddEnigmaDataEncryption();

using ServiceProvider provider = services.BuildServiceProvider();

IArgon2DataEncryptionService service = provider.GetRequiredService<IArgon2DataEncryptionService>();

char[] password = "correct horse battery staple".ToCharArray();

using MemoryStream input = new(Encoding.UTF8.GetBytes("Attack at dawn."));
using MemoryStream container = new();

await service.EncryptAsync(input, container, Cipher.Aes256Gcm, password);

Console.WriteLine($"{container.Length} bytes written");
```

In a hosted application the call goes on the host builder's collection instead — `builder.Services
.AddEnigmaDataEncryption();` — and everything below applies unchanged.

### Inject into your own type

Depend on the interfaces, never on the implementations: that is what makes the service substitutable in a
test.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption;

public sealed class DocumentVault
{
    private readonly IArgon2DataEncryptionService encryption;
    private readonly IEncryptedDataInspector inspector;

    public DocumentVault(
        IArgon2DataEncryptionService encryption,
        IEncryptedDataInspector inspector)
    {
        this.encryption = encryption;
        this.inspector = inspector;
    }

    public Task StoreAsync(
        string plainPath,
        string vaultPath,
        char[] password,
        CancellationToken cancellationToken = default) =>
        encryption.EncryptFileAsync(
            plainPath, vaultPath, Cipher.Aes256Gcm, password,
            cancellationToken: cancellationToken);

    public async Task<EncryptionMethod> DescribeAsync(
        string vaultPath,
        CancellationToken cancellationToken = default)
    {
        using FileStream container = File.OpenRead(vaultPath);

        EncryptedDataHeader header = await inspector.ReadHeaderAsync(
            container, cancellationToken: cancellationToken);

        return header.Method;
    }
}
```

and register it alongside:

```csharp
using Microsoft.Extensions.DependencyInjection;

ServiceCollection services = new();
services.AddEnigmaDataEncryption();
services.AddSingleton<DocumentVault>();

using ServiceProvider provider = services.BuildServiceProvider();
DocumentVault vault = provider.GetRequiredService<DocumentVault>();
```

`DocumentVault` can be a singleton too, because the services it holds are. The file-path extension
methods used above are described in [File operations](file-operations.md).

### Resolve every service at once

All five are registered, so a type that dispatches on a container's method can take all of them:

```csharp
using System;
using Enigma.DataEncryption;
using Microsoft.Extensions.DependencyInjection;

ServiceCollection services = new();
services.AddEnigmaDataEncryption();

using ServiceProvider provider = services.BuildServiceProvider();

IPbkdf2DataEncryptionService pbkdf2 = provider.GetRequiredService<IPbkdf2DataEncryptionService>();
IArgon2DataEncryptionService argon2 = provider.GetRequiredService<IArgon2DataEncryptionService>();
IRsaDataEncryptionService rsa = provider.GetRequiredService<IRsaDataEncryptionService>();
IMLKemDataEncryptionService mlKem = provider.GetRequiredService<IMLKemDataEncryptionService>();
IEncryptedDataInspector inspector = provider.GetRequiredService<IEncryptedDataInspector>();

// Singletons: resolving twice returns the same instance.
Console.WriteLine(ReferenceEquals(argon2, provider.GetRequiredService<IArgon2DataEncryptionService>()));  // True
```

See [Header inspection](header-inspection.md) for the detect-then-dispatch pattern these five enable.

### Override a registration

Because every registration uses `TryAdd`, **registering first wins**. That applies to this library's own
services and to the Enigma.Core factories underneath them:

```csharp
using Enigma.Core.Symmetric.BlockCiphers;
using Microsoft.Extensions.DependencyInjection;

ServiceCollection services = new();

// Register the block-cipher factory yourself — substitute your own implementation of
// IBlockCipherServiceFactory here, e.g. one that counts invocations or enforces a policy.
services.AddSingleton<IBlockCipherServiceFactory>(new BlockCipherServiceFactory());

// The four services are now built on top of yours; every other registration is added as usual.
services.AddEnigmaDataEncryption();
```

Overriding one of this library's own services works the same way — a decorator, a stub for a test, or a
service that logs every call:

```csharp
using Enigma.DataEncryption;
using Microsoft.Extensions.DependencyInjection;

ServiceCollection services = new();

// Yours is kept; AddEnigmaDataEncryption() will not replace it.
services.AddSingleton<IArgon2DataEncryptionService>(new Argon2DataEncryptionService());
services.AddEnigmaDataEncryption();
```

Calling `AddEnigmaDataEncryption()` twice is likewise harmless: the second call adds nothing.

### Use the library without a container

Every implementation has a **public parameterless constructor** that wires Enigma.Core's default
factories, so no container is needed:

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncryption;

// Each of these is complete and ready to use.
IPbkdf2DataEncryptionService pbkdf2 = new Pbkdf2DataEncryptionService();
IArgon2DataEncryptionService argon2 = new Argon2DataEncryptionService();
IRsaDataEncryptionService rsa = new RsaDataEncryptionService();
IMLKemDataEncryptionService mlKem = new MLKemDataEncryptionService();
IEncryptedDataInspector inspector = new EncryptedDataInspector();

char[] password = "correct horse battery staple".ToCharArray();

using MemoryStream input = new(Encoding.UTF8.GetBytes("Attack at dawn."));
using MemoryStream container = new();

await argon2.EncryptAsync(input, container, Cipher.Aes256Gcm, password);

Console.WriteLine($"{container.Length} bytes written");
```

Because the services are stateless and thread-safe, holding them in a `static readonly` field is a
perfectly good substitute for a container in a small application.

For the cases in between — no container, but you want to supply the Enigma.Core factories yourself — each
service also has a public constructor taking them:

```csharp
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption;

IBlockCipherServiceFactory blockCiphers = new BlockCipherServiceFactory();
IHmacServiceFactory hmacs = new HmacServiceFactory();

IArgon2DataEncryptionService argon2 =
    new Argon2DataEncryptionService(blockCiphers, new Argon2ServiceFactory(), hmacs);

IPbkdf2DataEncryptionService pbkdf2 =
    new Pbkdf2DataEncryptionService(blockCiphers, new Pbkdf2ServiceFactory(), hmacs);

IRsaDataEncryptionService rsa =
    new RsaDataEncryptionService(blockCiphers, new PublicKeyServiceFactory(), hmacs);

IMLKemDataEncryptionService mlKem =
    new MLKemDataEncryptionService(blockCiphers, new MLKemServiceFactory(), hmacs);
```

This is the constructor a container resolves. Each parameter throws `ArgumentNullException` if `null`.

## Notes

- **The library references only `Microsoft.Extensions.DependencyInjection.Abstractions`.** Your
  application supplies the concrete container. That is why `BuildServiceProvider()` in the snippets above
  needs the `Microsoft.Extensions.DependencyInjection` package.
- **Everything is a singleton, and that is a property of the services, not a default to reconsider.** They
  hold no mutable state; a scoped or transient registration would allocate more objects to do exactly the
  same work.
- **`TryAdd` means registering first wins.** There is no `Replace`-style overload and no options object —
  substitute by registering your own implementation *before* calling `AddEnigmaDataEncryption()`.
- **The Enigma.Core factories are part of the public registration**, so you can inject and use them
  directly for anything this library does not cover — RSA key generation via `IPublicKeyServiceFactory`,
  ML-KEM key generation via `IMLKemServiceFactory`. See [RSA](rsa.md) and [ML-KEM](ml-kem.md).
- **Inject the interfaces, not the implementations.** The five `I*` interfaces are the substitutable seam;
  the file-path extension methods are declared on them, so a test double gets those for free.
- **No `AddEnigmaCore` exists to call first.** Enigma.Core ships no registration extension by design, and
  this method covers the factories this library needs. If you consume Enigma.Core for other purposes in
  the same application, its factories are already registered here for you.
