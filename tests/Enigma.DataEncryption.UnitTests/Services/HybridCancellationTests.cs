using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Cancellation of the hybrid method, at both of the points where it matters: before the call does anything,
/// and in the middle of the payload.
/// </summary>
/// <remarks>
/// The pre-cancelled cases are checked with poisoned RSA <b>and</b> ML-KEM factories, so "a cancelled call
/// does no key work" covers both primitives rather than whichever one happens to run first.
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(HybridKeyCollection.Name)]
public sealed class HybridCancellationTests(HybridKeyFixture keys)
{
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;

    // --- Cancelled before the call ------------------------------------------------------------------

    [Fact]
    public async Task EncryptWithAnAlreadyCancelledTokenDoesNoKeyWork()
    {
        HybridDataEncryptionService service = HybridTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory(),
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(HybridTestData.Plaintext(1_024), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                Default, null, cancelled.Token));

        Assert.Equal(0, output.Length);
    }

    /// <summary>
    /// Decryption too: the cancellation is observed before the header is parsed, so a cancelled call does not
    /// even read the container.
    /// </summary>
    [Fact]
    public async Task DecryptWithAnAlreadyCancelledTokenReadsNothing()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(1_024),
            Cipher.Aes256Gcm, Default);

        HybridDataEncryptionService service = HybridTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory(),
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.DecryptAsync(
                input, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
                cancelled.Token));

        Assert.Equal(0, input.Position);
        Assert.Equal(0, output.Length);
    }

    // --- Cancelled during the payload stage ---------------------------------------------------------

    /// <summary>
    /// Cancelled from inside the payload: the token is tripped by the input stream itself, part-way through,
    /// which is the only way to show the payload stage is cancellable rather than just its entry.
    /// </summary>
    [Fact]
    public async Task EncryptIsCancellableDuringThePayload()
    {
        const int size = 4 * 1024 * 1024;

        using CancellationTokenSource cancelAfterFirstChunks = new();
        using PatternStream plaintext = new(size);
        using CancelAfterStream input = new(plaintext, 8_192, cancelAfterFirstChunks);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => HybridTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                Default, null, cancelAfterFirstChunks.Token));

        // It stopped early — the whole payload was never consumed.
        Assert.True(
            plaintext.BytesRead < size,
            $"The cancelled encryption still read all {size} input bytes.");
    }

    [Fact]
    public async Task DecryptIsCancellableDuringThePayload()
    {
        const int size = 4 * 1024 * 1024;
        HybridDataEncryptionService service = HybridTestData.Service();

        using PatternStream plaintext = new(size);
        using MemoryStream container = new();
        await service.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
            Default, null, TestContext.Current.CancellationToken);

        container.Position = 0;
        using CancellationTokenSource cancelAfterFirstChunks = new();
        using CancelAfterStream input = new(
            container, HybridTestData.HeaderLengthOf(Default) + 8_192, cancelAfterFirstChunks);
        using MemoryStream recovered = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.DecryptAsync(
                input, recovered, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
                cancelAfterFirstChunks.Token));

        Assert.True(
            recovered.Length < size,
            $"The cancelled decryption still produced all {size} plaintext bytes.");
    }

    /// <summary>A token that is never cancelled changes nothing, of course.</summary>
    [Fact]
    public async Task ALiveTokenLetsTheOperationComplete()
    {
        HybridDataEncryptionService service = HybridTestData.Service();
        byte[] plaintext = HybridTestData.Plaintext(4_096);

        using CancellationTokenSource live = new();
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), Default,
            null, live.Token);

        container.Position = 0;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
            live.Token);

        Assert.Equal(plaintext, recovered.ToArray());
    }
}
