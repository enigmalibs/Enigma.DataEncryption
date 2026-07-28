using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Proves the key-clearing contract for the RSA method instead of asserting it in a comment: the generated
/// data key and the unwrapped one are both zeroed by the time a call returns — and are zeroed even when the
/// call fails part-way.
/// </summary>
/// <remarks>
/// The predecessor library's code review raised exactly this as its one High-severity finding, caused by
/// clearing outside <c>try/finally</c>. The spies here hold the very arrays the production code was handed
/// or handed back: on encrypt the data key comes from <see cref="IRandomSource"/>, on decrypt it comes out
/// of Enigma.Core's OAEP unwrap, so both sides need their own spy.
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(RsaKeyCollection.Name)]
public sealed class RsaKeyMaterialClearingTests(RsaKeyFixture keys)
{
    [Fact]
    public async Task EncryptClearsTheGeneratedDataKey()
    {
        RecordingRandomSource randomSource = new();
        using MemoryStream input = new(RsaTestData.Plaintext(128), writable: false);
        using MemoryStream output = new();

        await RsaTestData.Service(randomSource).EncryptAsync(
            input, output, Cipher.Aes256Gcm, keys.PublicKeyPem, null, TestContext.Current.CancellationToken);

        AssertIssuedDataKeysWereUsedThenCleared(randomSource);
    }

    /// <summary>An encrypt that fails at the wrap must not leave the generated key behind either.</summary>
    [Fact]
    public async Task AFailedEncryptStillClearsTheGeneratedDataKey()
    {
        RecordingRandomSource randomSource = new();
        using MemoryStream input = new(RsaTestData.Plaintext(128), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => RsaTestData.Service(randomSource).EncryptAsync(
                input, output, Cipher.Aes256Gcm, RsaTestData.NotAPem, null, TestContext.Current.CancellationToken));

        AssertIssuedDataKeysWereUsedThenCleared(randomSource);
    }

    [Fact]
    public async Task DecryptClearsTheUnwrappedDataKey()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(128));
        RecordingPublicKeyServiceFactory recorder = new();

        await RsaTestData.DecryptToBytesAsync(
            keys.PrivateKeyPem, container, service: RsaTestData.Service(publicKeyServiceFactory: recorder));

        AssertUnwrappedKeysWereUsedThenCleared(recorder);
    }

    /// <summary>
    /// The <c>finally</c> has to enclose the failure paths too. Key confirmation fails here — the wrapped
    /// key was replaced with one holding a different 32-byte key — so the unwrapped key must still be gone.
    /// </summary>
    [Fact]
    public async Task ADecryptThatFailsKeyConfirmationStillClearsTheUnwrappedDataKey()
    {
        byte[] header = await RsaTestData.BuildHeaderAsync(
            RsaTestData.WrapOaep(
                FormatTestData.Sequence(0xA0, DataEncryptionDefaults.DataKeySizeBytes), keys.PublicKeyPem),
            FormatTestData.DataKey());
        RecordingPublicKeyServiceFactory recorder = new();

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.Service(publicKeyServiceFactory: recorder).DecryptAsync(
                input, output, keys.PrivateKeyPem,
                cancellationToken: TestContext.Current.CancellationToken));

        AssertUnwrappedKeysWereUsedThenCleared(recorder);
    }

    /// <summary>And a payload that fails authentication, which fails later still.</summary>
    [Fact]
    public async Task ATamperedPayloadStillClearsTheUnwrappedDataKey()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(128));
        container[^1] ^= 0x01;
        RecordingPublicKeyServiceFactory recorder = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(
                keys.PrivateKeyPem, container, service: RsaTestData.Service(publicKeyServiceFactory: recorder)));

        AssertUnwrappedKeysWereUsedThenCleared(recorder);
    }

    /// <summary>
    /// A wrapped key of the wrong length is cleared as well: it is rejected as a format error, and the
    /// bytes it held are still key material.
    /// </summary>
    [Fact]
    public async Task AWrappedKeyOfTheWrongLengthIsClearedBeforeItIsRejected()
    {
        byte[] header = await RsaTestData.BuildHeaderAsync(
            RsaTestData.WrapOaep(FormatTestData.Sequence(0x70, 16), keys.PublicKeyPem),
            FormatTestData.DataKey());
        RecordingPublicKeyServiceFactory recorder = new();

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.Service(publicKeyServiceFactory: recorder).DecryptAsync(
                input, output, keys.PrivateKeyPem,
                cancellationToken: TestContext.Current.CancellationToken));

        AssertUnwrappedKeysWereUsedThenCleared(recorder);
    }

    private static void AssertIssuedDataKeysWereUsedThenCleared(RecordingRandomSource randomSource)
    {
        Assert.NotEmpty(randomSource.IssuedDataKeys);

        for (int i = 0; i < randomSource.Issued.Count; i++)
        {
            byte[] buffer = randomSource.Issued[i];
            if (buffer.Length != DataEncryptionDefaults.DataKeySizeBytes) continue;

            // The snapshot proves the test is not passing on a key that was zero to begin with.
            Assert.Contains((byte)0x01, Nonzero(randomSource.Snapshots[i]));
            Assert.All(buffer, value => Assert.Equal(0, value));
        }
    }

    private static void AssertUnwrappedKeysWereUsedThenCleared(RecordingPublicKeyServiceFactory recorder)
    {
        Assert.NotEmpty(recorder.UnwrappedKeys);

        for (int i = 0; i < recorder.UnwrappedKeys.Count; i++)
        {
            Assert.Contains((byte)0x01, Nonzero(recorder.Snapshots[i]));
            Assert.All(recorder.UnwrappedKeys[i], value => Assert.Equal(0, value));
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
