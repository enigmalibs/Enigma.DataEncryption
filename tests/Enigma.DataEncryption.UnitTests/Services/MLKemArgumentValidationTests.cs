using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The argument matrix of the ML-KEM service: null streams, a null or empty key, an undefined
/// <see cref="Cipher"/> and an undefined <see cref="MLKemParameterSet"/>.
/// </summary>
/// <remarks>
/// Two things are asserted beyond the exception type. First, the <c>paramName</c>, because a caller acts on
/// it. Second, that the rejection happens <b>before any work</b> — nothing is written to the output stream and
/// no KEM operation is attempted — which is step 1 of <c>docs/format.md</c> §7.1.
/// </remarks>
/// <param name="keys">The shared key material.</param>
// ReSharper disable once InconsistentNaming
[Collection(MLKemKeyCollection.Name)]
public sealed class MLKemArgumentValidationTests(MLKemKeyFixture keys)
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
                () => MLKemTestData.Service().EncryptAsync(
                    null!, stream, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => MLKemTestData.Service().EncryptAsync(
                    stream, null!, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Decrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => MLKemTestData.Service().DecryptAsync(
                    null!, stream, keys.PrivateKey(Default), null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => MLKemTestData.Service().DecryptAsync(
                    stream, null!, keys.PrivateKey(Default), null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    // --- The key material ---------------------------------------------------------------------------

    [Fact]
    public async Task NullKey_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "publicKey",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => MLKemTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, null!, Default, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "privateKey",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => MLKemTestData.Service().DecryptAsync(
                    input, output, null!, null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task EmptyKey_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentException publicKey = await Assert.ThrowsAsync<ArgumentException>(
            () => MLKemTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, [], Default, null, TestContext.Current.CancellationToken));
        Assert.Equal("publicKey", publicKey.ParamName);

        ArgumentException privateKey = await Assert.ThrowsAsync<ArgumentException>(
            () => MLKemTestData.Service().DecryptAsync(
                input, output, [], null, null, TestContext.Current.CancellationToken));
        Assert.Equal("privateKey", privateKey.ParamName);
    }

    /// <summary>The caller's key arrays are neither mutated nor cleared — the XML docs promise they own them.</summary>
    [Fact]
    public async Task TheCallersKeyArraysSurviveTheCall()
    {
        byte[] publicKey = keys.PublicKey(Default);
        byte[] privateKey = keys.PrivateKey(Default);
        byte[] publicBefore = (byte[])publicKey.Clone();
        byte[] privateBefore = (byte[])privateKey.Clone();
        byte[] plaintext = MLKemTestData.Plaintext(64);

        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            publicKey, plaintext, Cipher.Aes256Gcm, Default);
        Assert.Equal(plaintext, await MLKemTestData.DecryptToBytesAsync(privateKey, container));

        Assert.Equal(publicBefore, publicKey);
        Assert.Equal(privateBefore, privateKey);
    }

    // --- The cipher and the parameter set -----------------------------------------------------------

    [Fact]
    public async Task Encrypt_UndefinedCipher_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => MLKemTestData.Service().EncryptAsync(
                input, output, UndefinedCipher, keys.PublicKey(Default), Default, null, TestContext.Current.CancellationToken));

        Assert.Equal("cipher", exception.ParamName);

        // The interface's XML docs name ArgumentException for this case; ArgumentOutOfRangeException is one,
        // so a caller catching either is satisfied.
        Assert.IsAssignableFrom<ArgumentException>(exception);
    }

    /// <summary>
    /// An undefined parameter set is rejected by this library rather than by Enigma.Core's factory, so the
    /// call faults synchronously — before a nonce is drawn or a key is touched.
    /// </summary>
    [Fact]
    public async Task Encrypt_UndefinedParameterSet_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => MLKemTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKey(Default), UndefinedParameterSet, null, TestContext.Current.CancellationToken));

        Assert.Equal("parameterSet", exception.ParamName);
        Assert.IsAssignableFrom<ArgumentException>(exception);
    }

    /// <summary>
    /// Validation runs in declaration order, so the first parameter at fault is the one reported: the cipher
    /// before the key, and the key before the parameter set.
    /// </summary>
    [Fact]
    public async Task ValidationReportsTheFirstFaultyParameterInDeclarationOrder()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "cipher",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => MLKemTestData.Service().EncryptAsync(
                    input, output, UndefinedCipher, null!, UndefinedParameterSet, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "publicKey",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => MLKemTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, null!, UndefinedParameterSet, null, TestContext.Current.CancellationToken))).ParamName);
    }

    // --- Nothing happens before validation ----------------------------------------------------------

    /// <summary>
    /// A rejected call writes nothing and encapsulates nothing: the output stream is untouched, the input is
    /// never read, and the poisoned KEM factory — which throws the moment it is used — is never reached.
    /// </summary>
    [Fact]
    public async Task ARejectedCallWritesNothingAndTouchesNoKey()
    {
        MLKemDataEncryptionService service = MLKemTestData.Service(
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());
        using MemoryStream input = new(MLKemTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, [], Default, null, TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.EncryptAsync(
                input, output, UndefinedCipher, keys.PublicKey(Default), Default, null, TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKey(Default), UndefinedParameterSet, null, TestContext.Current.CancellationToken));

        Assert.Equal(0, output.Length);
        Assert.Equal(0, input.Position);
    }

    /// <summary>A rejected decrypt does not even read the container.</summary>
    [Fact]
    public async Task ARejectedDecryptReadsNothing()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => MLKemTestData.Service(mlKemServiceFactory: new PoisonedMLKemServiceFactory())
                .DecryptAsync(input, output, [], null, null, TestContext.Current.CancellationToken));

        Assert.Equal(0, input.Position);
        Assert.Equal(0, output.Length);
    }

    // --- The constructors ---------------------------------------------------------------------------

    [Fact]
    public void TheConstructorRejectsNullFactories()
    {
        Assert.Throws<ArgumentNullException>(
            () => new MLKemDataEncryptionService(null!, new MLKemServiceFactory(), new Core.Hashing.Hmac.HmacServiceFactory()));

        Assert.Throws<ArgumentNullException>(
            () => new MLKemDataEncryptionService(new Core.Symmetric.BlockCiphers.BlockCipherServiceFactory(), null!, new Core.Hashing.Hmac.HmacServiceFactory()));

        Assert.Throws<ArgumentNullException>(
            () => new MLKemDataEncryptionService(new Core.Symmetric.BlockCiphers.BlockCipherServiceFactory(), new MLKemServiceFactory(), null!));
    }

    /// <summary>The parameterless constructor produces a working service — the no-container path.</summary>
    [Fact]
    public async Task TheParameterlessConstructorProducesAWorkingService()
    {
        MLKemDataEncryptionService service = new();
        byte[] plaintext = MLKemTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null, TestContext.Current.CancellationToken);

        container.Position = 0;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.PrivateKey(Default), null, null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, recovered.ToArray());
    }
}
