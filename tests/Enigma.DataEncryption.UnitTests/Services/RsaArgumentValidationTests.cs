using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
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
                    null!, stream, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => RsaTestData.Service().EncryptAsync(
                    stream, null!, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
                    TestContext.Current.CancellationToken))).ParamName);
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
                    input, output, Cipher.Aes256Gcm, null!, RsaOaepHash.Sha256, null,
                    TestContext.Current.CancellationToken))).ParamName);

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
                input, output, Cipher.Aes256Gcm, string.Empty, RsaOaepHash.Sha256, null,
                TestContext.Current.CancellationToken));
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
                input, output, UndefinedCipher, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
                TestContext.Current.CancellationToken));

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
                input, output, UndefinedCipher, null!, RsaOaepHash.Sha256, null,
                TestContext.Current.CancellationToken));

        Assert.Equal("cipher", exception.ParamName);
    }

    // --- The OAEP hash ------------------------------------------------------------------------------

    private const RsaOaepHash UndefinedOaepHash = (RsaOaepHash)0x7F;

    /// <summary>
    /// SHA-1 is <b>rejected</b>, not merely discouraged: the format reserves its wire byte and accepts no
    /// container carrying it (<c>docs/format.md</c> §3.3, §10), so an argument naming it cannot be honoured.
    /// </summary>
    [Fact]
    public async Task Encrypt_Sha1_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => RsaTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha1, null,
                TestContext.Current.CancellationToken));

        Assert.Equal("oaepHash", exception.ParamName);
        Assert.IsAssignableFrom<ArgumentException>(exception);
    }

    [Fact]
    public async Task Encrypt_UndefinedOaepHash_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => RsaTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKeyPem, UndefinedOaepHash, null,
                TestContext.Current.CancellationToken));

        Assert.Equal("oaepHash", exception.ParamName);
    }

    /// <summary>
    /// Declaration order again: the cipher before the key, and the key before the hash — so a caller who got
    /// two parameters wrong is told about the first one.
    /// </summary>
    [Fact]
    public async Task ValidationReportsTheFirstFaultyParameterInDeclarationOrder()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "cipher",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => RsaTestData.Service().EncryptAsync(
                    input, output, UndefinedCipher, keys.PublicKeyPem, RsaOaepHash.Sha1, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "publicKeyPem",
            (await Assert.ThrowsAsync<ArgumentException>(
                () => RsaTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, string.Empty, RsaOaepHash.Sha1, null,
                    TestContext.Current.CancellationToken))).ParamName);
    }

    /// <summary>
    /// A rejected hash reaches no key and writes nothing: the poisoned RSA factory throws the moment it is
    /// used, and it is never used.
    /// </summary>
    [Fact]
    public async Task ARejectedOaepHashTouchesNoKeyAndWritesNothing()
    {
        RsaDataEncryptionService service = RsaTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory());
        using MemoryStream input = new(RsaTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        foreach (RsaOaepHash rejected in new[] { RsaOaepHash.Sha1, UndefinedOaepHash })
        {
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => service.EncryptAsync(
                    input, output, Cipher.Aes256Gcm, keys.PublicKeyPem, rejected, null,
                    TestContext.Current.CancellationToken));
        }

        Assert.Equal(0, output.Length);
        Assert.Equal(0, input.Position);
    }

    // --- The OAEP hash, on the file-path extension ---------------------------------------------------

    /// <summary>
    /// The extension validates the hash <b>before either file is opened</b>. That ordering is load-bearing:
    /// the output is <c>FileMode.Create</c>, so validating later would truncate a caller's existing file only
    /// to delete it again. The assertion is therefore that the pre-existing output file is left intact and
    /// the never-created one is not created.
    /// </summary>
    [Theory]
    [InlineData(RsaOaepHash.Sha1)]
    [InlineData(UndefinedOaepHash)]
    public async Task EncryptFile_RejectsTheHashBeforeOpeningEitherFile(RsaOaepHash rejected)
    {
        using TempWorkspace workspace = new();
        string inputPath = workspace.WriteFile("plaintext.bin", RsaTestData.Plaintext(64));
        string missingOutputPath = workspace.PathFor("container.bin");

        byte[] existingContent = [0x11, 0x22, 0x33];
        string existingOutputPath = workspace.WriteFile("existing.bin", existingContent);

        IRsaDataEncryptionService service = RsaTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory());

        Assert.Equal(
            "oaepHash",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => service.EncryptFileAsync(
                    inputPath, missingOutputPath, Cipher.Aes256Gcm, keys.PublicKeyPem, rejected,
                    cancellationToken: TestContext.Current.CancellationToken))).ParamName);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.EncryptFileAsync(
                inputPath, existingOutputPath, Cipher.Aes256Gcm, keys.PublicKeyPem, rejected,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(File.Exists(missingOutputPath), "The output file was created before the hash was validated.");
        Assert.Equal(existingContent, File.ReadAllBytes(existingOutputPath));
    }

    /// <summary>
    /// A missing input file is not what rejects the call either — the hash is checked before the path is
    /// even resolved, so the outcome does not depend on the file system at all.
    /// </summary>
    [Fact]
    public async Task EncryptFile_RejectsTheHashEvenWhenTheInputDoesNotExist()
    {
        using TempWorkspace workspace = new();

        Assert.Equal(
            "oaepHash",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => RsaTestData.Service().EncryptFileAsync(
                    workspace.PathFor("no-such-file.bin"),
                    workspace.PathFor("container.bin"),
                    Cipher.Aes256Gcm,
                    keys.PublicKeyPem,
                    RsaOaepHash.Sha1,
                    cancellationToken: TestContext.Current.CancellationToken))).ParamName);
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
                input, output, Cipher.Aes256Gcm, string.Empty, RsaOaepHash.Sha256, null,
                TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.EncryptAsync(
                input, output, UndefinedCipher, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
                TestContext.Current.CancellationToken));

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
            input, container, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
            TestContext.Current.CancellationToken);

        container.Position = 0;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, recovered.ToArray());
    }
}
