using System;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.DependencyInjection;

/// <summary>
/// Registration tests for <c>AddEnigmaDataEncryption()</c>, driven through a real
/// <see cref="ServiceCollection"/> and <see cref="ServiceProvider"/>. They assert wiring only —
/// resolution, lifetime and <c>TryAdd</c> semantics — never behaviour, which is still
/// <see cref="NotImplementedException"/> until FEATURE-11B6.
/// </summary>
public sealed class ServiceCollectionExtensionsTests
{
    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddEnigmaDataEncryption().BuildServiceProvider();

    [Theory]
    [InlineData(typeof(IPbkdf2DataEncryptionService))]
    [InlineData(typeof(IArgon2DataEncryptionService))]
    [InlineData(typeof(IRsaDataEncryptionService))]
    [InlineData(typeof(IMLKemDataEncryptionService))]
    [InlineData(typeof(IEncryptedDataInspector))]
    public void AddEnigmaDataEncryption_ResolvesEveryService(Type serviceType)
    {
        using ServiceProvider provider = BuildProvider();

        Assert.NotNull(provider.GetRequiredService(serviceType));
    }

    [Theory]
    [InlineData(typeof(IBlockCipherServiceFactory))]
    [InlineData(typeof(IPbkdf2ServiceFactory))]
    [InlineData(typeof(IArgon2ServiceFactory))]
    [InlineData(typeof(IPublicKeyServiceFactory))]
    [InlineData(typeof(IMLKemServiceFactory))]
    [InlineData(typeof(IHmacServiceFactory))]
    public void AddEnigmaDataEncryption_ResolvesTheEnigmaCoreFactories(Type factoryType)
    {
        using ServiceProvider provider = BuildProvider();

        Assert.NotNull(provider.GetRequiredService(factoryType));
    }

    [Theory]
    [InlineData(typeof(IPbkdf2DataEncryptionService))]
    [InlineData(typeof(IArgon2DataEncryptionService))]
    [InlineData(typeof(IRsaDataEncryptionService))]
    [InlineData(typeof(IMLKemDataEncryptionService))]
    [InlineData(typeof(IEncryptedDataInspector))]
    public void AddEnigmaDataEncryption_RegistersServicesAsSingletons(Type serviceType)
    {
        using ServiceProvider provider = BuildProvider();

        Assert.Same(provider.GetRequiredService(serviceType), provider.GetRequiredService(serviceType));
    }

    [Fact]
    public void AddEnigmaDataEncryption_ReturnsTheSameCollection_ForChaining()
    {
        var services = new ServiceCollection();

        IServiceCollection returned = services.AddEnigmaDataEncryption();

        Assert.Same(services, returned);
    }

    [Fact]
    public void AddEnigmaDataEncryption_Throws_WhenServicesIsNull()
    {
        IServiceCollection services = null!;

        Assert.Throws<ArgumentNullException>(() => services.AddEnigmaDataEncryption());
    }

    /// <summary>
    /// The point of <c>TryAdd*</c>: a consumer who has already registered their own Enigma.Core
    /// factory keeps it, and the resolved encryption services are built against it.
    /// </summary>
    [Fact]
    public void AddEnigmaDataEncryption_KeepsAPreRegisteredFactory()
    {
        var custom = new StubBlockCipherServiceFactory();
        var services = new ServiceCollection();
        services.AddSingleton<IBlockCipherServiceFactory>(custom);

        using ServiceProvider provider = services.AddEnigmaDataEncryption().BuildServiceProvider();

        Assert.Same(custom, provider.GetRequiredService<IBlockCipherServiceFactory>());
    }

    [Fact]
    public void AddEnigmaDataEncryption_IsIdempotent()
    {
        using ServiceProvider provider = new ServiceCollection()
            .AddEnigmaDataEncryption()
            .AddEnigmaDataEncryption()
            .BuildServiceProvider();

        // A second call must not shadow the first with a duplicate registration.
        Assert.NotNull(provider.GetRequiredService<IPbkdf2DataEncryptionService>());
        Assert.Single(provider.GetServices<IPbkdf2DataEncryptionService>());
    }

    /// <summary>
    /// A stand-in <see cref="IBlockCipherServiceFactory"/> used only to prove <c>TryAdd*</c> survival —
    /// its identity is what the test asserts, so no member is ever invoked.
    /// </summary>
    private sealed class StubBlockCipherServiceFactory : IBlockCipherServiceFactory
    {
        public IBlockCipherService CreateAesService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateDesService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateTripleDesService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateBlowfishService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateTwofishService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateSerpentService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateCamelliaService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateCast128Service(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateIdeaService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateSeedService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateAriaService(int bufferSize = 4096) => throw new NotSupportedException();
        public IBlockCipherService CreateSm4Service(int bufferSize = 4096) => throw new NotSupportedException();
    }
}
