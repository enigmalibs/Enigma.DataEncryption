using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Cancellation of the ML-KEM method, at both of the points where it matters: before the call does anything,
/// and in the middle of the payload.
/// </summary>
/// <remarks>
/// The pre-cancelled case is checked with a KEM factory that throws if it is used at all, so "a cancelled call
/// does no key work" is proved rather than assumed — the same shape PHASE02 used for the key derivations and
/// PHASE03 for the RSA operations.
/// </remarks>
/// <param name="keys">The shared key material.</param>
// ReSharper disable once InconsistentNaming
[Collection(MLKemKeyCollection.Name)]
public sealed class MLKemCancellationTests(MLKemKeyFixture keys)
{
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;

    // --- Cancelled before the call ------------------------------------------------------------------

    [Fact]
    public async Task EncryptWithAnAlreadyCancelledTokenEncapsulatesNothing()
    {
        MLKemDataEncryptionService service = MLKemTestData.Service(
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(MLKemTestData.Plaintext(1_024), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null, cancelled.Token));

        Assert.Equal(0, output.Length);
    }

    /// <summary>
    /// Decryption too: the cancellation is observed before the header is parsed, so a cancelled call does not
    /// even read the container.
    /// </summary>
    [Fact]
    public async Task DecryptWithAnAlreadyCancelledTokenReadsNothing()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(1_024), Cipher.Aes256Gcm, Default);

        MLKemDataEncryptionService service = MLKemTestData.Service(
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.DecryptAsync(input, output, keys.PrivateKey(Default), null, null, cancelled.Token));

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
            () => MLKemTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null,
                cancelAfterFirstChunks.Token));

        // It stopped early — the whole payload was never consumed.
        Assert.True(
            plaintext.BytesRead < size,
            $"The cancelled encryption still read all {size} input bytes.");
    }

    [Fact]
    public async Task DecryptIsCancellableDuringThePayload()
    {
        const int size = 4 * 1024 * 1024;
        MLKemDataEncryptionService service = MLKemTestData.Service();

        using PatternStream plaintext = new(size);
        using MemoryStream container = new();
        await service.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null,
            TestContext.Current.CancellationToken);

        container.Position = 0;
        using CancellationTokenSource cancelAfterFirstChunks = new();
        using CancelAfterStream input = new(
            container, MLKemTestData.HeaderLengthOf(Default) + 8_192, cancelAfterFirstChunks);
        using MemoryStream recovered = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.DecryptAsync(
                input, recovered, keys.PrivateKey(Default), null, null, cancelAfterFirstChunks.Token));

        Assert.True(
            recovered.Length < size,
            $"The cancelled decryption still produced all {size} plaintext bytes.");
    }

    /// <summary>A token that is never cancelled changes nothing, of course.</summary>
    [Fact]
    public async Task ALiveTokenLetsTheOperationComplete()
    {
        MLKemDataEncryptionService service = MLKemTestData.Service();
        byte[] plaintext = MLKemTestData.Plaintext(4_096);

        using CancellationTokenSource live = new();
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null, live.Token);

        container.Position = 0;
        using MemoryStream recovered = new();
        await service.DecryptAsync(container, recovered, keys.PrivateKey(Default), null, null, live.Token);

        Assert.Equal(plaintext, recovered.ToArray());
    }
}
