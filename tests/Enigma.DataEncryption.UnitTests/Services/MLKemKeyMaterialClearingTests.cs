using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Proves the key-clearing contract for the ML-KEM method instead of asserting it in a comment: the
/// encapsulated shared secret and the decapsulated one are both zeroed by the time a call returns — and are
/// zeroed even when the call fails part-way.
/// </summary>
/// <remarks>
/// The predecessor library's code review raised exactly this as its one High-severity finding, caused by
/// clearing outside <c>try/finally</c>. Both of this method's secrets are allocated inside Enigma.Core — the
/// encapsulated one on the way out, the decapsulated one on the way back — so a single recording factory
/// holds the very arrays the production code was handed, on both sides.
/// </remarks>
/// <param name="keys">The shared key material.</param>
// ReSharper disable once InconsistentNaming
[Collection(MLKemKeyCollection.Name)]
public sealed class MLKemKeyMaterialClearingTests(MLKemKeyFixture keys)
{
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;

    [Fact]
    public async Task EncryptClearsTheEncapsulatedSharedSecret()
    {
        RecordingMLKemServiceFactory recorder = new();

        await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default),
            MLKemTestData.Plaintext(128),
            Cipher.Aes256Gcm,
            Default,
            MLKemTestData.Service(mlKemServiceFactory: recorder));

        AssertSecretsWereUsedThenCleared(recorder, recorder.EncapsulatedSecrets);
    }

    /// <summary>
    /// An encrypt that fails during the payload must not leave the encapsulated secret behind either. The
    /// output stream here refuses to be written past the header, so the failure lands inside the payload stage,
    /// after the secret has been used.
    /// </summary>
    [Fact]
    public async Task AFailedEncryptStillClearsTheEncapsulatedSharedSecret()
    {
        RecordingMLKemServiceFactory recorder = new();
        using MemoryStream input = new(MLKemTestData.Plaintext(4_096), writable: false);
        using ThrowAfterStream output = new(MLKemTestData.HeaderLengthOf(Default));

        await Assert.ThrowsAsync<IOException>(
            () => MLKemTestData.Service(mlKemServiceFactory: recorder).EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKey(Default), Default, null,
                TestContext.Current.CancellationToken));

        AssertSecretsWereUsedThenCleared(recorder, recorder.EncapsulatedSecrets);
    }

    [Fact]
    public async Task DecryptClearsTheDecapsulatedSharedSecret()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(128), Cipher.Aes256Gcm, Default);
        RecordingMLKemServiceFactory recorder = new();

        await MLKemTestData.DecryptToBytesAsync(
            keys.PrivateKey(Default),
            container,
            service: MLKemTestData.Service(mlKemServiceFactory: recorder));

        AssertSecretsWereUsedThenCleared(recorder, recorder.DecapsulatedSecrets);
    }

    /// <summary>
    /// The <c>finally</c> has to enclose the failure paths too — and for ML-KEM the wrong-key path is exactly
    /// where a secret <i>does</i> get produced, because implicit rejection means decapsulation succeeded. The
    /// wrong secret is still key material and must still be gone.
    /// </summary>
    [Fact]
    public async Task ADecryptThatFailsKeyConfirmationStillClearsTheDecapsulatedSharedSecret()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(128), Cipher.Aes256Gcm, Default);
        RecordingMLKemServiceFactory recorder = new();

        using PoisonedPayloadStream input = new(container[..MLKemTestData.HeaderLengthOf(Default)]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.Service(mlKemServiceFactory: recorder).DecryptAsync(
                input, output, keys.UnrelatedPrivateKey(Default), null, null,
                TestContext.Current.CancellationToken));

        AssertSecretsWereUsedThenCleared(recorder, recorder.DecapsulatedSecrets);
    }

    /// <summary>And a payload that fails authentication, which fails later still.</summary>
    [Fact]
    public async Task ATamperedPayloadStillClearsTheDecapsulatedSharedSecret()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(128), Cipher.Aes256Gcm, Default);
        container[^1] ^= 0x01;
        RecordingMLKemServiceFactory recorder = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(
                keys.PrivateKey(Default),
                container,
                service: MLKemTestData.Service(mlKemServiceFactory: recorder)));

        AssertSecretsWereUsedThenCleared(recorder, recorder.DecapsulatedSecrets);
    }

    private static void AssertSecretsWereUsedThenCleared(
        RecordingMLKemServiceFactory recorder,
        List<byte[]> secrets)
    {
        Assert.NotEmpty(secrets);
        Assert.Equal(secrets.Count, recorder.Snapshots.Count);

        for (int i = 0; i < secrets.Count; i++)
        {
            // The snapshot proves the test is not passing on a secret that was zero to begin with.
            Assert.Contains((byte)0x01, Nonzero(recorder.Snapshots[i]));
            Assert.All(secrets[i], value => Assert.Equal(0, value));
        }
    }

    /// <summary>Maps a buffer to a marker per non-zero byte, so "was it ever non-zero" is assertable.</summary>
    private static byte[] Nonzero(byte[] buffer)
    {
        byte[] markers = new byte[buffer.Length];
        for (int i = 0; i < buffer.Length; i++)
        {
            markers[i] = buffer[i] == 0 ? (byte)0x00 : (byte)0x01;
        }

        return markers;
    }
}
