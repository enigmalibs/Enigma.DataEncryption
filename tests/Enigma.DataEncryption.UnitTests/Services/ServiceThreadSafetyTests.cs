using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Drives <b>one instance</b> of each of the six services from many tasks at once, on distinct payloads,
/// and checks every result.
/// </summary>
/// <remarks>
/// <para>
/// This is what substantiates the singleton registration. <c>AddEnigmaDataEncryption()</c> registers all
/// six as singletons on the stated grounds that they are stateless — every key, nonce and buffer lives on
/// the stack of the call — and a claim of that kind is worth more as a test than as a comment. The failure
/// it would catch is a field promoted from local to instance during some later refactor: correct under a
/// single caller, silently wrong under two.
/// </para>
/// <para>
/// <b>Distinct payloads per task are the point.</b> Concurrent work on identical inputs can pass while
/// state is being shared, because every task wants the same answer. Giving each task its own length and
/// its own cipher means a leaked buffer or a shared nonce shows up as a wrong plaintext, not merely as a
/// race that happens not to matter.
/// </para>
/// </remarks>
public sealed class ServiceThreadSafetyTests
{
    /// <summary>How many tasks share the one instance.</summary>
    private const int Concurrency = 32;

    /// <summary>The five methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<ContainerMethodKind> Methods() => [.. ContainerMethodHarness.All];

    /// <summary>
    /// One harness — and therefore one service instance — encrypting and decrypting concurrently. Every
    /// task uses its own payload length and cipher, and asserts its own round-trip.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task OneInstanceRoundTripsConcurrently(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        Cipher[] ciphers = ContainerMethodHarness.AllCiphers;

        Task[] tasks = Enumerable.Range(0, Concurrency).Select(index => Task.Run(async () =>
        {
            byte[] plaintext = ContainerFixtures.Plaintext(64 + (index * 37));
            Cipher cipher = ciphers[index % ciphers.Length];

            byte[] container = await harness.EncryptToBytesAsync(plaintext, cipher);
            byte[] recovered = await harness.DecryptToBytesAsync(container);

            Assert.Equal(plaintext, recovered);
        })).ToArray();

        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// The same instance decrypting many <i>different</i> containers at once. A shared nonce or data-key
    /// buffer would cross-contaminate here even though each container is individually valid.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task OneInstanceDecryptsDistinctContainersConcurrently(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);

        (byte[] Plaintext, byte[] Container)[] pairs = new (byte[], byte[])[Concurrency];
        for (int index = 0; index < pairs.Length; index++)
        {
            byte[] plaintext = ContainerFixtures.Plaintext(32 + (index * 11));
            pairs[index] = (plaintext, await harness.EncryptToBytesAsync(plaintext));
        }

        Task[] tasks = pairs.Select(pair => Task.Run(async () =>
        {
            byte[] recovered = await harness.DecryptToBytesAsync(pair.Container);
            Assert.Equal(pair.Plaintext, recovered);
        })).ToArray();

        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Concurrent failures alongside concurrent successes. A wrong credential on one task must not affect
    /// what another task recovers — the case where shared state would be most likely to produce a
    /// <i>silently wrong</i> result rather than an exception.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ConcurrentFailuresDoNotDisturbConcurrentSuccesses(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(512);
        byte[] container = await harness.EncryptToBytesAsync(plaintext);

        Task[] tasks = Enumerable.Range(0, Concurrency).Select(index => Task.Run(async () =>
        {
            if (index % 2 == 0)
            {
                Assert.Equal(plaintext, await harness.DecryptToBytesAsync(container));
            }
            else
            {
                await Assert.ThrowsAsync<DataDecryptionException>(
                    () => harness.DecryptWithWrongCredentialToBytesAsync(container));
            }
        })).ToArray();

        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// The sixth service. The inspector has no dependencies and no credential, so the only state it could
    /// share is the header buffer itself — which is exactly what would corrupt a concurrent parse.
    /// </summary>
    [Fact]
    public async Task TheInspectorReadsConcurrently()
    {
        IEncryptedDataInspector inspector = new EncryptedDataInspector();
        CancellationToken token = TestContext.Current.CancellationToken;

        HeaderShape[] shapes = FormatTestData.AllShapes;
        byte[][] headers = new byte[shapes.Length][];
        for (int i = 0; i < shapes.Length; i++)
        {
            headers[i] = await FormatTestData.BuildHeaderAsync(shapes[i]);
        }

        Task[] tasks = Enumerable.Range(0, Concurrency).Select(index => Task.Run(async () =>
        {
            int which = index % headers.Length;
            using MemoryStream input = new(headers[which], writable: false);

            EncryptedDataHeader parsed = await inspector.ReadHeaderAsync(input, null, token);

            Assert.Equal(FormatTestData.MethodOf(shapes[which]), parsed.Method);
            Assert.Equal(FormatTestData.HeaderLengthOf(shapes[which]), parsed.HeaderLength);
        })).ToArray();

        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// The concrete singletons, resolved exactly as a container would build them, driven concurrently
    /// across <i>all</i> six at once — so the interleaving is between different services sharing the same
    /// Enigma.Core factories, not just between calls into one.
    /// </summary>
    [Fact]
    public async Task AllSixSingletonsWorkConcurrentlyTogether()
    {
        IBlockCipherServiceFactory blockCiphers = new BlockCipherServiceFactory();
        IHmacServiceFactory hmacs = new HmacServiceFactory();

        IPbkdf2DataEncryptionService pbkdf2 =
            new Pbkdf2DataEncryptionService(blockCiphers, new Pbkdf2ServiceFactory(), hmacs);
        IArgon2DataEncryptionService argon2 =
            new Argon2DataEncryptionService(blockCiphers, new Argon2ServiceFactory(), hmacs);
        IRsaDataEncryptionService rsa =
            new RsaDataEncryptionService(blockCiphers, new PublicKeyServiceFactory(), hmacs);
        IMLKemDataEncryptionService kem =
            new MLKemDataEncryptionService(blockCiphers, new MLKemServiceFactory(), hmacs);
        IHybridDataEncryptionService hybrid = new HybridDataEncryptionService(
            blockCiphers, new PublicKeyServiceFactory(), new MLKemServiceFactory(), hmacs);
        IEncryptedDataInspector inspector = new EncryptedDataInspector();
        CancellationToken token = TestContext.Current.CancellationToken;

        ConcurrentBag<EncryptionMethod> inspected = [];

        Task[] tasks = Enumerable.Range(0, Concurrency).Select(index => Task.Run(async () =>
        {
            byte[] plaintext = ContainerFixtures.Plaintext(48 + (index * 13));
            byte[] container = (index % 5) switch
            {
                0 => await RoundTripAsync(
                    (i, o) => pbkdf2.EncryptAsync(
                        i, o, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(),
                        ContainerMethodHarness.Pbkdf2Iterations, null, token),
                    (i, o) => pbkdf2.DecryptAsync(i, o, PasswordTestData.PasswordBytes(), null, null, token),
                    plaintext),
                1 => await RoundTripAsync(
                    (i, o) => argon2.EncryptAsync(
                        i, o, Cipher.Twofish256Gcm, PasswordTestData.PasswordBytes(),
                        ContainerMethodHarness.Argon2Iterations, ContainerMethodHarness.Argon2MemorySizeKb,
                        ContainerMethodHarness.Argon2DegreeOfParallelism, null, token),
                    (i, o) => argon2.DecryptAsync(i, o, PasswordTestData.PasswordBytes(), null, null, token),
                    plaintext),
                2 => await RoundTripAsync(
                    (i, o) => rsa.EncryptAsync(
                        i, o, Cipher.Serpent256Gcm, RsaTestData.GoldenPublicKeyPem(), null, token),
                    (i, o) => rsa.DecryptAsync(i, o, RsaTestData.GoldenPrivateKeyPem(), null, null, null, token),
                    plaintext),
                3 => await RoundTripAsync(
                    (i, o) => kem.EncryptAsync(
                        i, o, Cipher.Camellia256Gcm, MLKemTestData.GoldenPublicKey("512"),
                        MLKemParameterSet.MLKem512, null, token),
                    (i, o) => kem.DecryptAsync(i, o, MLKemTestData.GoldenPrivateKey("512"), null, null, token),
                    plaintext),
                _ => await RoundTripAsync(
                    (i, o) => hybrid.EncryptAsync(
                        i, o, Cipher.Aes256Gcm, RsaTestData.GoldenPublicKeyPem(),
                        MLKemTestData.GoldenPublicKey("512"), MLKemParameterSet.MLKem512, null, token),
                    (i, o) => hybrid.DecryptAsync(
                        i, o, RsaTestData.GoldenPrivateKeyPem(), MLKemTestData.GoldenPrivateKey("512"),
                        null, null, null, token),
                    plaintext),
            };

            using MemoryStream headerInput = new(container, writable: false);
            inspected.Add((await inspector.ReadHeaderAsync(headerInput, null, token)).Method);
        })).ToArray();

        await Task.WhenAll(tasks);

        Assert.Equal(Concurrency, inspected.Count);
        Assert.Contains(EncryptionMethod.Pbkdf2, inspected);
        Assert.Contains(EncryptionMethod.Argon2, inspected);
        Assert.Contains(EncryptionMethod.Rsa, inspected);
        Assert.Contains(EncryptionMethod.MLKem, inspected);
        Assert.Contains(EncryptionMethod.Hybrid, inspected);
    }

    /// <summary>
    /// Encrypts a plaintext, decrypts it back, asserts they match, and returns the container so the caller
    /// can go on to inspect it.
    /// </summary>
    /// <param name="encrypt">The encrypt call.</param>
    /// <param name="decrypt">The decrypt call.</param>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <returns>The container bytes.</returns>
    private static async Task<byte[]> RoundTripAsync(
        Func<Stream, Stream, Task> encrypt,
        Func<Stream, Stream, Task> decrypt,
        byte[] plaintext)
    {
        using MemoryStream source = new(plaintext, writable: false);
        using MemoryStream container = new();
        await encrypt(source, container);

        byte[] containerBytes = container.ToArray();

        using MemoryStream encrypted = new(containerBytes, writable: false);
        using MemoryStream recovered = new();
        await decrypt(encrypted, recovered);

        Assert.Equal(plaintext, recovered.ToArray());

        return containerBytes;
    }
}
