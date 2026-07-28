using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption;
using Enigma.DataEncryption.UnitTests.Services;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.DependencyInjection;

/// <summary>
/// Registration tests for <c>AddEnigmaDataEncryption()</c>, driven through a real
/// <see cref="ServiceCollection"/> and <see cref="ServiceProvider"/>: resolution, lifetime,
/// <c>TryAdd</c> semantics — and, now that every service is implemented, a full round-trip through the
/// resolved instances.
/// </summary>
/// <remarks>
/// The round-trip at the end is what makes the rest of this class more than a registration checklist. It
/// is the only test that exercises the composition a consumer actually gets: the internal
/// <c>IRandomSource</c> seam resolved from the container rather than passed to a constructor, and each
/// service built by the explicit factory lambda that reaches its internal constructor.
/// </remarks>
public sealed class ServiceCollectionExtensionsTests
{
    private static ServiceProvider BuildProvider() =>
        new ServiceCollection().AddEnigmaDataEncryption().BuildServiceProvider();

    [Theory]
    [InlineData(typeof(IPbkdf2DataEncryptionService))]
    [InlineData(typeof(IArgon2DataEncryptionService))]
    [InlineData(typeof(IRsaDataEncryptionService))]
    [InlineData(typeof(IMLKemDataEncryptionService))]
    [InlineData(typeof(IHybridDataEncryptionService))]
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
    [InlineData(typeof(IHybridDataEncryptionService))]
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
    /// A pre-registered factory is not merely kept in the collection — the encryption services resolved
    /// afterwards are built <i>against</i> it. That is what <c>TryAdd*</c> is for, and asserting only the
    /// factory's identity would miss a registration that shadowed it inside the service lambdas.
    /// </summary>
    [Fact]
    public async Task APreRegisteredFactoryIsWhatTheResolvedServicesUse()
    {
        var custom = new StubBlockCipherServiceFactory();
        var services = new ServiceCollection();
        services.AddSingleton<IBlockCipherServiceFactory>(custom);

        using ServiceProvider provider = services.AddEnigmaDataEncryption().BuildServiceProvider();
        var pbkdf2 = provider.GetRequiredService<IPbkdf2DataEncryptionService>();

        using MemoryStream input = new([1, 2, 3], writable: false);
        using MemoryStream output = new();

        // The stub throws from every factory method, so reaching the payload stage proves which factory
        // the service was handed.
        await Assert.ThrowsAsync<NotSupportedException>(
            () => pbkdf2.EncryptAsync(
                input, output, Cipher.Aes256Gcm, PasswordBytes, 1_000, null,
                TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The whole registration, end to end: every service resolved from the container round-trips a payload,
    /// and the inspector reads back the header each one wrote.
    /// </summary>
    [Fact]
    public async Task TheResolvedServicesRoundTripAPayload()
    {
        using ServiceProvider provider = BuildProvider();

        var pbkdf2 = provider.GetRequiredService<IPbkdf2DataEncryptionService>();
        var argon2 = provider.GetRequiredService<IArgon2DataEncryptionService>();
        var rsa = provider.GetRequiredService<IRsaDataEncryptionService>();
        var kem = provider.GetRequiredService<IMLKemDataEncryptionService>();
        var hybrid = provider.GetRequiredService<IHybridDataEncryptionService>();
        var inspector = provider.GetRequiredService<IEncryptedDataInspector>();

        CancellationToken token = TestContext.Current.CancellationToken;
        byte[] plaintext = ContainerFixtures.Plaintext(256);

        await AssertRoundTripAsync(
            EncryptionMethod.Pbkdf2,
            (i, o) => pbkdf2.EncryptAsync(i, o, Cipher.Aes256Gcm, PasswordBytes, 1_000, null, token),
            (i, o) => pbkdf2.DecryptAsync(i, o, PasswordBytes, null, null, token));

        await AssertRoundTripAsync(
            EncryptionMethod.Argon2,
            (i, o) => argon2.EncryptAsync(i, o, Cipher.Twofish256Gcm, PasswordBytes, 1, 1_024, 1, null, token),
            (i, o) => argon2.DecryptAsync(i, o, PasswordBytes, null, null, token));

        await AssertRoundTripAsync(
            EncryptionMethod.Rsa,
            (i, o) => rsa.EncryptAsync(i, o, Cipher.Serpent256Gcm, RsaTestData.GoldenPublicKeyPem(), null, token),
            (i, o) => rsa.DecryptAsync(
                i, o, RsaTestData.GoldenPrivateKeyPem(), null, null, null, token));

        await AssertRoundTripAsync(
            EncryptionMethod.MLKem,
            (i, o) => kem.EncryptAsync(
                i, o, Cipher.Camellia256Gcm, MLKemTestData.GoldenPublicKey("512"),
                MLKemParameterSet.MLKem512, null, token),
            (i, o) => kem.DecryptAsync(i, o, MLKemTestData.GoldenPrivateKey("512"), null, null, token));

        // The hybrid takes four Enigma.Core factories rather than three, so its registration lambda is the
        // one most likely to be missing a dependency — a round-trip through the resolved instance is what
        // catches that.
        await AssertRoundTripAsync(
            EncryptionMethod.Hybrid,
            (i, o) => hybrid.EncryptAsync(
                i, o, Cipher.Aes256Gcm, RsaTestData.GoldenPublicKeyPem(),
                MLKemTestData.GoldenPublicKey("512"), MLKemParameterSet.MLKem512, null, token),
            (i, o) => hybrid.DecryptAsync(
                i, o, RsaTestData.GoldenPrivateKeyPem(), MLKemTestData.GoldenPrivateKey("512"), null, null,
                null, token));

        async Task AssertRoundTripAsync(
            EncryptionMethod expectedMethod,
            Func<Stream, Stream, Task> encrypt,
            Func<Stream, Stream, Task> decrypt)
        {
            using MemoryStream source = new(plaintext, writable: false);
            using MemoryStream container = new();
            await encrypt(source, container);

            byte[] containerBytes = container.ToArray();

            using MemoryStream forInspection = new(containerBytes, writable: false);
            EncryptedDataHeader header = await inspector.ReadHeaderAsync(forInspection, null, token);
            Assert.Equal(expectedMethod, header.Method);

            using MemoryStream encrypted = new(containerBytes, writable: false);
            using MemoryStream recovered = new();
            await decrypt(encrypted, recovered);

            Assert.Equal(plaintext, recovered.ToArray());
        }
    }

    /// <summary>
    /// The file-path extensions compose with the resolved interfaces — they are extension methods on the
    /// interfaces precisely so that they do.
    /// </summary>
    [Fact]
    public async Task TheFileExtensionsComposeWithTheResolvedServices()
    {
        using ServiceProvider provider = BuildProvider();
        var pbkdf2 = provider.GetRequiredService<IPbkdf2DataEncryptionService>();

        byte[] plaintext = ContainerFixtures.Plaintext(128);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await pbkdf2.EncryptFileAsync(
            plainPath, containerPath, Cipher.Aes256Gcm, PasswordBytes, 1_000,
            cancellationToken: TestContext.Current.CancellationToken);
        await pbkdf2.DecryptFileAsync(
            containerPath, recoveredPath, PasswordBytes,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));
    }

    /// <summary>The password the round-trips above use — its bytes matter not at all, only its stability.</summary>
    private static byte[] PasswordBytes => Encoding.UTF8.GetBytes("resolved-from-the-container");

    /// <summary>
    /// A stand-in <see cref="IBlockCipherServiceFactory"/> used only to prove <c>TryAdd*</c> survival —
    /// its identity is what most of the tests assert, so no member needs to work.
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
