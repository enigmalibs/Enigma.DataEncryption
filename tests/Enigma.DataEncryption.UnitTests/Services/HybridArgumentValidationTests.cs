using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The argument matrix of the hybrid service: null streams, a null or empty key of either kind, an
/// undefined <see cref="Cipher"/> and an undefined <see cref="MLKemParameterSet"/>.
/// </summary>
/// <remarks>
/// <para>
/// Two things are asserted beyond the exception type. First, the <c>paramName</c>, because a caller acts on
/// it — and this is the one method with two credentials, so "which key did I get wrong" is a question the
/// exception has to answer. Second, that the rejection happens <b>before any work</b>: nothing is written to
/// the output stream and neither public-key primitive is touched, which is step 1 of
/// <c>docs/format.md</c> §7.1.
/// </para>
/// <para>
/// Validation order is declaration order, which for this method means the RSA key is reported before the
/// ML-KEM key. <see cref="ValidationReportsTheFirstFaultyParameterInDeclarationOrder"/> pins that, so a
/// caller who has both wrong is told about them in a stable order rather than an arbitrary one.
/// </para>
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(HybridKeyCollection.Name)]
public sealed class HybridArgumentValidationTests(HybridKeyFixture keys)
{
    private const Cipher UndefinedCipher = (Cipher)0x7F;
    private const MLKemParameterSet UndefinedParameterSet = (MLKemParameterSet)0x63;
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;

    // --- Null streams -------------------------------------------------------------------------------

    [Fact]
    public async Task Encrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().EncryptAsync(
                    null!, stream, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                    Default, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().EncryptAsync(
                    stream, null!, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                    Default, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Decrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().DecryptAsync(
                    null!, stream, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().DecryptAsync(
                    stream, null!, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
                    TestContext.Current.CancellationToken))).ParamName);
    }

    // --- The two credentials ------------------------------------------------------------------------

    [Fact]
    public async Task NullKeys_Throw()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "rsaPublicKeyPem",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, null!, keys.MLKemPublicKey(Default), Default, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "mlKemPublicKey",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, null!, Default, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "rsaPrivateKeyPem",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().DecryptAsync(
                    input, output, null!, keys.MLKemPrivateKey(Default), null, null, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "mlKemPrivateKey",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().DecryptAsync(
                    input, output, keys.RsaPrivateKeyPem, null!, null, null, null,
                    TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task EmptyKeys_Throw()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "rsaPublicKeyPem",
            (await Assert.ThrowsAsync<ArgumentException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, string.Empty, keys.MLKemPublicKey(Default), Default,
                    null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "mlKemPublicKey",
            (await Assert.ThrowsAsync<ArgumentException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, [], Default, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "rsaPrivateKeyPem",
            (await Assert.ThrowsAsync<ArgumentException>(
                () => HybridTestData.Service().DecryptAsync(
                    input, output, string.Empty, keys.MLKemPrivateKey(Default), null, null, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "mlKemPrivateKey",
            (await Assert.ThrowsAsync<ArgumentException>(
                () => HybridTestData.Service().DecryptAsync(
                    input, output, keys.RsaPrivateKeyPem, [], null, null, null,
                    TestContext.Current.CancellationToken))).ParamName);
    }

    /// <summary>
    /// The caller's key arrays and passphrase are neither mutated nor cleared — the XML docs promise the
    /// caller owns them, and this method holds three such buffers rather than one.
    /// </summary>
    [Fact]
    public async Task TheCallersCredentialsSurviveTheCall()
    {
        byte[] publicKey = keys.MLKemPublicKey(Default);
        byte[] privateKey = keys.MLKemPrivateKey(Default);
        byte[] publicBefore = (byte[])publicKey.Clone();
        byte[] privateBefore = (byte[])privateKey.Clone();
        char[] passphrase = keys.PemPassphraseChars();
        byte[] plaintext = HybridTestData.Plaintext(64);

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.EncryptedPemRsaPublicKeyPem, publicKey, plaintext, Cipher.Aes256Gcm, Default);

        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.EncryptedRsaPrivateKeyPem, privateKey, container, passphrase));

        Assert.Equal(publicBefore, publicKey);
        Assert.Equal(privateBefore, privateKey);
        Assert.Equal(keys.PemPassphraseChars(), passphrase);
    }

    // --- The cipher and the parameter set -----------------------------------------------------------

    [Fact]
    public async Task Encrypt_UndefinedCipher_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => HybridTestData.Service().EncryptAsync(
                input, output, UndefinedCipher, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), Default,
                null, TestContext.Current.CancellationToken));

        Assert.Equal("cipher", exception.ParamName);

        // The interface's XML docs name ArgumentException for this case; ArgumentOutOfRangeException is one,
        // so a caller catching either is satisfied.
        Assert.IsAssignableFrom<ArgumentException>(exception);
    }

    [Fact]
    public async Task Encrypt_UndefinedParameterSet_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => HybridTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                UndefinedParameterSet, null, TestContext.Current.CancellationToken));

        Assert.Equal("parameterSet", exception.ParamName);
        Assert.IsAssignableFrom<ArgumentException>(exception);
    }

    /// <summary>
    /// Validation runs in declaration order, so the first parameter at fault is the one reported: the cipher
    /// before the RSA key, the RSA key before the ML-KEM key, and the ML-KEM key before the parameter set.
    /// </summary>
    [Fact]
    public async Task ValidationReportsTheFirstFaultyParameterInDeclarationOrder()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "cipher",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, UndefinedCipher, null!, null!, UndefinedParameterSet, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "rsaPublicKeyPem",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, null!, null!, UndefinedParameterSet, null,
                    TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "mlKemPublicKey",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, null!, UndefinedParameterSet,
                    null, TestContext.Current.CancellationToken))).ParamName);

        // Both keys good, only the parameter set wrong.
        Assert.Equal(
            "parameterSet",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                    UndefinedParameterSet, null, TestContext.Current.CancellationToken))).ParamName);

        // On decrypt: the RSA key before the ML-KEM key.
        Assert.Equal(
            "rsaPrivateKeyPem",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => HybridTestData.Service().DecryptAsync(
                    input, output, null!, null!, null, null, null,
                    TestContext.Current.CancellationToken))).ParamName);
    }

    // --- Nothing happens before validation ----------------------------------------------------------

    /// <summary>
    /// A rejected call writes nothing and touches neither primitive: the output stream is untouched, the
    /// input is never read, and the poisoned RSA and ML-KEM factories — which throw the moment they are
    /// used — are never reached.
    /// </summary>
    [Fact]
    public async Task ARejectedCallWritesNothingAndTouchesNoKey()
    {
        HybridDataEncryptionService service = HybridTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory(),
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());
        using MemoryStream input = new(HybridTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, string.Empty, keys.MLKemPublicKey(Default), Default, null,
                TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, [], Default, null,
                TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.EncryptAsync(
                input, output, UndefinedCipher, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), Default,
                null, TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                UndefinedParameterSet, null, TestContext.Current.CancellationToken));

        Assert.Equal(0, output.Length);
        Assert.Equal(0, input.Position);
    }

    /// <summary>A rejected decrypt does not even read the container.</summary>
    [Fact]
    public async Task ARejectedDecryptReadsNothing()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();
        HybridDataEncryptionService service = HybridTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory(),
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.DecryptAsync(
                input, output, string.Empty, keys.MLKemPrivateKey(Default), null, null, null,
                TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.DecryptAsync(
                input, output, keys.RsaPrivateKeyPem, [], null, null, null,
                TestContext.Current.CancellationToken));

        Assert.Equal(0, input.Position);
        Assert.Equal(0, output.Length);
    }

    // --- The constructors ---------------------------------------------------------------------------

    /// <summary>
    /// All four factories are required. This service takes one more than any other, so the null guard is
    /// swept rather than spot-checked.
    /// </summary>
    [Fact]
    public void TheConstructorRejectsNullFactories()
    {
        IBlockCipherServiceFactory blockCiphers = new BlockCipherServiceFactory();
        IPublicKeyServiceFactory publicKeys = new PublicKeyServiceFactory();
        IMLKemServiceFactory kems = new MLKemServiceFactory();
        IHmacServiceFactory hmacs = new HmacServiceFactory();

        Assert.Equal(
            "blockCipherServiceFactory",
            Assert.Throws<ArgumentNullException>(
                () => new HybridDataEncryptionService(null!, publicKeys, kems, hmacs)).ParamName);

        Assert.Equal(
            "publicKeyServiceFactory",
            Assert.Throws<ArgumentNullException>(
                () => new HybridDataEncryptionService(blockCiphers, null!, kems, hmacs)).ParamName);

        Assert.Equal(
            "mlKemServiceFactory",
            Assert.Throws<ArgumentNullException>(
                () => new HybridDataEncryptionService(blockCiphers, publicKeys, null!, hmacs)).ParamName);

        Assert.Equal(
            "hmacServiceFactory",
            Assert.Throws<ArgumentNullException>(
                () => new HybridDataEncryptionService(blockCiphers, publicKeys, kems, null!)).ParamName);
    }

    /// <summary>The parameterless constructor produces a working service — the no-container path.</summary>
    [Fact]
    public async Task TheParameterlessConstructorProducesAWorkingService()
    {
        HybridDataEncryptionService service = new();
        byte[] plaintext = HybridTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), Default,
            null, TestContext.Current.CancellationToken);

        container.Position = 0;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
            TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, recovered.ToArray());
    }
}
