using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Proves the key-clearing contract for the hybrid method instead of asserting it in a comment: the RSA-half
/// secret, the ML-KEM shared secret <b>and the combined data key</b> are all zeroed by the time a call
/// returns — and are zeroed even when the call fails part-way.
/// </summary>
/// <remarks>
/// <para>
/// The predecessor library's code review raised exactly this as its one High-severity finding, caused by
/// clearing outside <c>try/finally</c>. This method holds three pieces of key material where the others hold
/// one, and they come from three different places: the RSA-half secret from the random source on encrypt and
/// from Enigma.Core's OAEP on decrypt, the shared secret from Enigma.Core's KEM in both directions, and the
/// combined key from the library's own combiner. Missing any one of them from the <c>finally</c> would be a
/// leak the round-trip tests could never see.
/// </para>
/// <para>
/// <b>The combined key is reached through the HMAC factory</b> rather than a seam of its own — see
/// <see cref="HmacKeyRecordingFactory"/> for why that works, and note that the same assertion sweeps all four
/// HMAC keys a call uses at once.
/// </para>
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(HybridKeyCollection.Name)]
public sealed class HybridKeyMaterialClearingTests(HybridKeyFixture keys)
{
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;

    // --- Encrypt ------------------------------------------------------------------------------------

    [Fact]
    public async Task EncryptClearsEveryPieceOfKeyMaterial()
    {
        HmacKeyRecordingFactory hmac = new();
        RecordingMLKemServiceFactory kem = new();
        RecordingRandomSource random = new();

        await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem,
            keys.MLKemPublicKey(Default),
            HybridTestData.Plaintext(128),
            Cipher.Aes256Gcm,
            Default,
            HybridTestData.Service(random, mlKemServiceFactory: kem, hmacServiceFactory: hmac));

        // The RSA-half secret came from the random source, by reference.
        AssertEveryBufferWasUsedThenCleared(random.IssuedDataKeys);

        // The shared secret came from the KEM, by reference.
        AssertSecretsWereUsedThenCleared(kem, kem.EncapsulatedSecrets);

        // And every HMAC key — which is those two plus the combined data key plus kcKey.
        AssertEveryHmacKeyWasCleared(hmac);
    }

    /// <summary>
    /// An encrypt that fails during the payload must not leave any of the three behind. The output stream
    /// here refuses to be written past the header, so the failure lands inside the payload stage — after all
    /// three have been established and used.
    /// </summary>
    [Fact]
    public async Task AFailedEncryptStillClearsEveryPieceOfKeyMaterial()
    {
        HmacKeyRecordingFactory hmac = new();
        RecordingMLKemServiceFactory kem = new();
        RecordingRandomSource random = new();

        using MemoryStream input = new(HybridTestData.Plaintext(4_096), writable: false);
        using ThrowAfterStream output = new(HybridTestData.HeaderLengthOf(Default));

        await Assert.ThrowsAsync<IOException>(
            () => HybridTestData.Service(random, mlKemServiceFactory: kem, hmacServiceFactory: hmac)
                .EncryptAsync(
                    input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
                    Default, null, TestContext.Current.CancellationToken));

        AssertEveryBufferWasUsedThenCleared(random.IssuedDataKeys);
        AssertSecretsWereUsedThenCleared(kem, kem.EncapsulatedSecrets);
        AssertEveryHmacKeyWasCleared(hmac);
    }

    // --- Decrypt ------------------------------------------------------------------------------------

    [Fact]
    public async Task DecryptClearsEveryPieceOfKeyMaterial()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(128),
            Cipher.Aes256Gcm, Default);

        HmacKeyRecordingFactory hmac = new();
        RecordingMLKemServiceFactory kem = new();
        RecordingPublicKeyServiceFactory rsa = new();

        await HybridTestData.DecryptToBytesAsync(
            keys.RsaPrivateKeyPem,
            keys.MLKemPrivateKey(Default),
            container,
            service: HybridTestData.Service(
                publicKeyServiceFactory: rsa, mlKemServiceFactory: kem, hmacServiceFactory: hmac));

        // The RSA-half secret was allocated inside Enigma.Core's OAEP unwrap.
        AssertEveryBufferWasUsedThenCleared(rsa.UnwrappedKeys);
        AssertSecretsWereUsedThenCleared(kem, kem.DecapsulatedSecrets);
        AssertEveryHmacKeyWasCleared(hmac);
    }

    /// <summary>
    /// The <c>finally</c> has to enclose the failure paths too — and for the hybrid the wrong-ML-KEM-key
    /// path is exactly where secrets <i>do</i> get produced, because implicit rejection means the
    /// decapsulation succeeded and the RSA unwrap succeeded before it. Both wrong-but-real secrets, and the
    /// wrong combined key derived from them, are still key material and must still be gone.
    /// </summary>
    [Fact]
    public async Task ADecryptThatFailsKeyConfirmationStillClearsEveryPieceOfKeyMaterial()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(128),
            Cipher.Aes256Gcm, Default);

        HmacKeyRecordingFactory hmac = new();
        RecordingMLKemServiceFactory kem = new();
        RecordingPublicKeyServiceFactory rsa = new();

        using PoisonedPayloadStream input = new(container[..HybridTestData.HeaderLengthOf(Default)]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.Service(
                    publicKeyServiceFactory: rsa, mlKemServiceFactory: kem, hmacServiceFactory: hmac)
                .DecryptAsync(
                    input, output, keys.RsaPrivateKeyPem, keys.UnrelatedMLKemPrivateKey(Default), null, null,
                    null, TestContext.Current.CancellationToken));

        AssertEveryBufferWasUsedThenCleared(rsa.UnwrappedKeys);
        AssertSecretsWereUsedThenCleared(kem, kem.DecapsulatedSecrets);
        AssertEveryHmacKeyWasCleared(hmac);
    }

    /// <summary>
    /// A decrypt that fails at the <b>RSA</b> half instead: the unwrap throws, so no secret was ever
    /// produced and there is nothing to leak — but the <c>finally</c> still has to cope with all three
    /// buffers being null, which is the case a careless implementation crashes on.
    /// </summary>
    [Fact]
    public async Task ADecryptThatFailsAtTheRsaHalfClearsNothingAndDoesNotThrowFromTheFinally()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(128),
            Cipher.Aes256Gcm, Default);

        RecordingMLKemServiceFactory kem = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.UnrelatedRsaPrivateKeyPem,
                keys.MLKemPrivateKey(Default),
                container,
                service: HybridTestData.Service(mlKemServiceFactory: kem)));

        // The RSA unwrap runs first and threw, so the ML-KEM half was never reached.
        Assert.Empty(kem.DecapsulatedSecrets);
    }

    /// <summary>And a payload that fails authentication, which fails later still.</summary>
    [Fact]
    public async Task ATamperedPayloadStillClearsEveryPieceOfKeyMaterial()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(128),
            Cipher.Aes256Gcm, Default);
        container[^1] ^= 0x01;

        HmacKeyRecordingFactory hmac = new();
        RecordingMLKemServiceFactory kem = new();
        RecordingPublicKeyServiceFactory rsa = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem,
                keys.MLKemPrivateKey(Default),
                container,
                service: HybridTestData.Service(
                    publicKeyServiceFactory: rsa, mlKemServiceFactory: kem, hmacServiceFactory: hmac)));

        AssertEveryBufferWasUsedThenCleared(rsa.UnwrappedKeys);
        AssertSecretsWereUsedThenCleared(kem, kem.DecapsulatedSecrets);
        AssertEveryHmacKeyWasCleared(hmac);
    }

    // --- Shared assertions --------------------------------------------------------------------------

    /// <summary>
    /// Every HMAC key the call used is zero afterwards — the four of them: both input secrets, the combined
    /// data key and <c>kcKey</c>.
    /// </summary>
    private static void AssertEveryHmacKeyWasCleared(HmacKeyRecordingFactory hmac)
    {
        // Two combiner branches plus the two of key confirmation. Fewer would mean the combiner or the tag
        // did not run at all, which would make the zero-check below vacuous.
        Assert.Equal(4, hmac.Keys.Count);

        for (int i = 0; i < hmac.Keys.Count; i++)
        {
            // The snapshot proves the test is not passing on a key that was zero to begin with.
            Assert.Contains((byte)0x01, Nonzero(hmac.Snapshots[i]));
            Assert.All(hmac.Keys[i], value => Assert.Equal(0, value));
        }
    }

    private static void AssertSecretsWereUsedThenCleared(
        RecordingMLKemServiceFactory recorder,
        List<byte[]> secrets)
    {
        Assert.NotEmpty(secrets);
        Assert.Equal(secrets.Count, recorder.Snapshots.Count);

        for (int i = 0; i < secrets.Count; i++)
        {
            Assert.Contains((byte)0x01, Nonzero(recorder.Snapshots[i]));
            Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, secrets[i].Length);
            Assert.All(secrets[i], value => Assert.Equal(0, value));
        }
    }

    private static void AssertEveryBufferWasUsedThenCleared(IEnumerable<byte[]> buffers)
    {
        int count = 0;
        foreach (byte[] buffer in buffers)
        {
            count++;
            Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, buffer.Length);
            Assert.All(buffer, value => Assert.Equal(0, value));
        }

        Assert.True(count > 0, "No data-key-sized buffer was recorded, so nothing was actually checked.");
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
