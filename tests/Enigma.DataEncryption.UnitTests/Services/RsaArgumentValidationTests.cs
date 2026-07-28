using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The argument matrix of the RSA service: null streams, a null or empty PEM, and an undefined
/// <see cref="Cipher"/> value.
/// </summary>
/// <remarks>
/// Two things are asserted beyond the exception type. First, the <c>paramName</c>, because a caller acts on
/// it. Second, that the rejection happens <b>before any work</b> — nothing is written to the output stream
/// and no private-key operation is attempted — which is step 1 of <c>docs/format.md</c> §7.1.
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(RsaKeyCollection.Name)]
public sealed class RsaArgumentValidationTests(RsaKeyFixture keys)
{
    private const Cipher UndefinedCipher = (Cipher)0x7F;

    // --- Null streams -------------------------------------------------------------------------------

    [Fact]
    public async Task Encrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => RsaTestData.Service().EncryptAsync(
                    null!, stream, Cipher.Aes256Gcm, keys.PublicKeyPem, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => RsaTestData.Service().EncryptAsync(
                    stream, null!, Cipher.Aes256Gcm, keys.PublicKeyPem, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Decrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => RsaTestData.Service().DecryptAsync(
                    null!, stream, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => RsaTestData.Service().DecryptAsync(
                    stream, null!, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    // --- The key material ---------------------------------------------------------------------------

    [Fact]
    public async Task NullPem_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "publicKeyPem",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => RsaTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, null!, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "privateKeyPem",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => RsaTestData.Service().DecryptAsync(
                    input, output, null!, null, null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task EmptyPem_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentException publicKey = await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, string.Empty, null, TestContext.Current.CancellationToken));
        Assert.Equal("publicKeyPem", publicKey.ParamName);

        ArgumentException privateKey = await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.Service().DecryptAsync(
                input, output, string.Empty, null, null, null, TestContext.Current.CancellationToken));
        Assert.Equal("privateKeyPem", privateKey.ParamName);
    }

    // --- The cipher ---------------------------------------------------------------------------------

    [Fact]
    public async Task Encrypt_UndefinedCipher_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => RsaTestData.Service().EncryptAsync(
                input, output, UndefinedCipher, keys.PublicKeyPem, null, TestContext.Current.CancellationToken));

        Assert.Equal("cipher", exception.ParamName);

        // The interface's XML docs name ArgumentException for this case; ArgumentOutOfRangeException is one,
        // so a caller catching either is satisfied.
        Assert.IsAssignableFrom<ArgumentException>(exception);
    }

    /// <summary>
    /// The cipher is validated before the credential is: an undefined cipher is reported even when the PEM
    /// is unusable too, because validation runs in declaration order.
    /// </summary>
    [Fact]
    public async Task Encrypt_UndefinedCipherIsReportedBeforeTheCredential()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => RsaTestData.Service().EncryptAsync(
                input, output, UndefinedCipher, null!, null, TestContext.Current.CancellationToken));

        Assert.Equal("cipher", exception.ParamName);
    }

    // --- Nothing happens before validation ----------------------------------------------------------

    /// <summary>
    /// A rejected call writes nothing and wraps nothing: the output stream is untouched, the input is never
    /// read, and the poisoned RSA factory — which throws the moment it is used — is never reached.
    /// </summary>
    [Fact]
    public async Task ARejectedCallWritesNothingAndTouchesNoKey()
    {
        RsaDataEncryptionService service = RsaTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory());
        using MemoryStream input = new(RsaTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, string.Empty, null, TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.EncryptAsync(
                input, output, UndefinedCipher, keys.PublicKeyPem, null, TestContext.Current.CancellationToken));

        Assert.Equal(0, output.Length);
        Assert.Equal(0, input.Position);
    }

    /// <summary>A rejected decrypt does not even read the container.</summary>
    [Fact]
    public async Task ARejectedDecryptReadsNothing()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.Service(publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory())
                .DecryptAsync(
                    input, output, string.Empty, null, null, null, TestContext.Current.CancellationToken));

        Assert.Equal(0, input.Position);
        Assert.Equal(0, output.Length);
    }

    // --- The constructors ---------------------------------------------------------------------------

    [Fact]
    public void TheConstructorRejectsNullFactories()
    {
        Assert.Throws<ArgumentNullException>(
            () => new RsaDataEncryptionService(null!, new Core.Asymmetric.PublicKey.PublicKeyServiceFactory(), new Core.Hashing.Hmac.HmacServiceFactory()));

        Assert.Throws<ArgumentNullException>(
            () => new RsaDataEncryptionService(new Core.Symmetric.BlockCiphers.BlockCipherServiceFactory(), null!, new Core.Hashing.Hmac.HmacServiceFactory()));

        Assert.Throws<ArgumentNullException>(
            () => new RsaDataEncryptionService(new Core.Symmetric.BlockCiphers.BlockCipherServiceFactory(), new Core.Asymmetric.PublicKey.PublicKeyServiceFactory(), null!));
    }

    /// <summary>The parameterless constructor produces a working service — the no-container path.</summary>
    [Fact]
    public async Task TheParameterlessConstructorProducesAWorkingService()
    {
        RsaDataEncryptionService service = new();
        byte[] plaintext = RsaTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.PublicKeyPem, null, TestContext.Current.CancellationToken);

        container.Position = 0;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, recovered.ToArray());
    }
}
