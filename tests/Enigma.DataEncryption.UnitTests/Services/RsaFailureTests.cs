using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The failure half of the RSA method: the wrong private key, an unusable credential, an edited header, a
/// tampered payload, and a wrapped-key length field out of bounds.
/// </summary>
/// <remarks>
/// <para>
/// Two properties here are about <b>when</b> the failure happens rather than merely that it does:
/// </para>
/// <list type="bullet">
///   <item><description>a wrong private key fails before a single payload byte is read — proved with a payload stream that throws if touched;</description></item>
///   <item><description>an out-of-bounds wrapped-key length fails before the private key is touched — proved with an RSA factory that throws if used.</description></item>
/// </list>
/// <para>
/// The third theme is the <b>credential-supply versus file-content</b> split of
/// <c>docs/format.md</c> §9: a PEM that cannot be parsed keeps its own exception and is never reshaped into
/// a container error, while an OAEP failure — which is all Enigma.Core gives us for a wrong key <i>and</i>
/// for an undecryptable PEM alike — becomes <see cref="DataDecryptionException"/> with the original kept
/// as the inner exception.
/// </para>
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(RsaKeyCollection.Name)]
public sealed class RsaFailureTests(RsaKeyFixture keys)
{
    /// <summary>All four ciphers.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher> Ciphers() => [.. RsaTestData.AllCiphers];

    /// <summary>Every named field of the RSA header, by offset (RSA-2048, so <c>N</c> = 256).</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string, int> HeaderFields() => new()
    {
        { "magic byte 0", 0 },
        { "magic byte 1", 1 },
        { "method", 2 },
        { "format version", 3 },
        { "cipher", 4 },
        { "OAEP hash", 5 },
        { "nonce (first byte)", 6 },
        { "nonce (last byte)", 17 },
        { "wrapped-key length (first byte)", 18 },
        { "wrapped-key length (last byte)", 21 },
        { "wrapped key (first byte)", 22 },
        { "wrapped key (middle byte)", 22 + (RsaTestData.WrappedKeyLength2048 / 2) },
        { "wrapped key (last byte)", 22 + RsaTestData.WrappedKeyLength2048 - 1 },
        { "key-confirmation tag (first byte)", 22 + RsaTestData.WrappedKeyLength2048 },
        { "key-confirmation tag (last byte)", RsaTestData.HeaderLength2048 - 1 },
    };

    // --- The wrong private key ----------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task TheWrongPrivateKeyIsADecryptionError(Cipher cipher)
    {
        byte[] plaintext = RsaTestData.Plaintext(256);
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext, cipher);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.UnrelatedPrivateKeyPem, container));

        // …and the other way round, so neither key is special.
        byte[] unrelatedContainer = await RsaTestData.EncryptToBytesAsync(
            keys.UnrelatedPublicKeyPem, plaintext, cipher);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, unrelatedContainer));
    }

    /// <summary>
    /// <b>The headline assertion of this phase.</b> A wrong private key is rejected while the container's
    /// payload is still untouched — the OAEP unwrap fails on the header's wrapped key alone. The payload
    /// here is a stream that throws if it is read at all, which turns "before a single payload byte is
    /// read" from a claim into a test.
    /// </summary>
    [Fact]
    public async Task TheWrongPrivateKeyFailsBeforeThePayloadIsRead()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(4_096));

        using PoisonedPayloadStream input = new(container[..RsaTestData.HeaderLength2048]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.Service().DecryptAsync(
                input, output, keys.UnrelatedPrivateKeyPem,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(input.PayloadWasRead);
        Assert.Equal(0, output.Length);
    }

    /// <summary>The right key, by contrast, does read the payload — the stream double is not the reason above.</summary>
    [Fact]
    public async Task TheRightPrivateKeyDoesReachThePayload()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        using PoisonedPayloadStream input = new(container[..RsaTestData.HeaderLength2048]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<IOException>(
            () => RsaTestData.Service().DecryptAsync(
                input, output, keys.PrivateKeyPem,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.True(input.PayloadWasRead);
    }

    /// <summary>A private key of a different size is wrong in a different way, and lands in the same place.</summary>
    [Fact]
    public async Task APrivateKeyOfADifferentSizeIsADecryptionError()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem3072, container));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem4096, container));
    }

    /// <summary>
    /// The key-confirmation tag is the backstop for the case OAEP cannot catch: a wrapped key that
    /// legitimately unwraps to 32 bytes of the <i>wrong</i> data key. A hostile sender holding the
    /// recipient's public key can build exactly that, so it is built here.
    /// </summary>
    [Fact]
    public async Task AWrappedKeyHoldingTheWrongDataKeyIsCaughtByKeyConfirmation()
    {
        // The wrapped key really does hold 32 bytes, and the tag really was computed under them — but the
        // tag in the header is the one the *real* data key would produce, so the two disagree.
        byte[] hostileKey = FormatTestData.Sequence(0xA0, DataEncryptionDefaults.DataKeySizeBytes);
        byte[] header = await RsaTestData.BuildHeaderAsync(
            RsaTestData.WrapOaep(hostileKey, keys.PublicKeyPem), FormatTestData.DataKey());

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.Service().DecryptAsync(
                input, output, keys.PrivateKeyPem,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("key-confirmation tag", exception.Message);
        Assert.False(input.PayloadWasRead);
    }

    /// <summary>
    /// And the case OAEP cannot catch either: a wrapped key that unwraps to something that is not
    /// 32 bytes long. Only a sender can produce this — it needs the recipient's public key — and without an
    /// explicit length check the short "data key" would reach the block cipher and surface as an unwrapped
    /// Enigma.Core exception.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public async Task AWrappedKeyThatDoesNotHoldA32ByteDataKeyIsAFormatError(int wrappedLength)
    {
        // The tag is computed under the real data key, which is beside the point: the length check runs
        // before key confirmation, so whatever the tag says cannot be what rejects this container.
        byte[] hostileKey = FormatTestData.Sequence(0x70, wrappedLength);
        byte[] header = await RsaTestData.BuildHeaderAsync(
            RsaTestData.WrapOaep(hostileKey, keys.PublicKeyPem), FormatTestData.DataKey());

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.Service().DecryptAsync(
                input, output, keys.PrivateKeyPem,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains($"{wrappedLength} bytes", exception.Message);
        Assert.False(input.PayloadWasRead);
    }

    // --- The credential itself ----------------------------------------------------------------------

    /// <summary>
    /// An encrypted PEM opened with the wrong passphrase, or with none at all, is a decryption error whose
    /// inner exception carries Enigma.Core's own diagnosis.
    /// </summary>
    /// <remarks>
    /// This is the amended row of <c>docs/format.md</c> §9. Enigma.Core reports a wrong key and an
    /// undecryptable PEM as the same <see cref="CryptographicException"/> from the same call, so they are
    /// not separable without matching on message text; both are wrapped, and the specific cause stays
    /// readable through <see cref="Exception.InnerException"/>.
    /// </remarks>
    [Fact]
    public async Task AnUndecryptablePrivateKeyPemIsADecryptionErrorWithTheCauseInside()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.EncryptedPemPublicKeyPem, RsaTestData.Plaintext(64));

        DataDecryptionException wrongPassphrase = await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(
                keys.EncryptedPrivateKeyPem, container, "not-the-passphrase".ToCharArray()));
        Assert.IsAssignableFrom<CryptographicException>(wrongPassphrase.InnerException);

        DataDecryptionException noPassphrase = await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.EncryptedPrivateKeyPem, container));
        Assert.IsAssignableFrom<CryptographicException>(noPassphrase.InnerException);
    }

    /// <summary>
    /// A PEM that cannot be <b>parsed</b> keeps its own identity: it is a credential-supply problem, not a
    /// statement about the container, so Enigma.Core's exception propagates untouched and is never reshaped
    /// into a <see cref="DataEncryptionException"/> (<c>docs/format.md</c> §9).
    /// </summary>
    [Fact]
    public async Task AnUnparseablePrivateKeyPemPropagatesUnwrapped()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        // Base64 that is not Base64. Under Enigma.Core 1.0.0 (BouncyCastle 2.6.2) the platform decoder's
        // FormatException escaped raw; Enigma.Core 1.1.0 (BouncyCastle 2.7.0) has PemReader wrap it in an
        // IOException, which Enigma.Core maps to ArgumentException. Both are §9 outcomes — this pins which
        // one, so the next drift is a red test. The FormatException is still there, nested below.
        ArgumentException malformed = await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.DecryptToBytesAsync(RsaTestData.MalformedPem, container));

        Assert.Equal("privateKeyPem", malformed.ParamName);
        Assert.NotNull(RsaTestData.FirstFormatException(malformed));

        // Text that is not a PEM, and a PEM that holds the wrong kind of key.
        foreach (string pem in new[] { RsaTestData.NotAPem, keys.PublicKeyPem })
        {
            ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
                () => RsaTestData.DecryptToBytesAsync(pem, container));

            Assert.Equal("privateKeyPem", exception.ParamName);
        }
    }

    /// <summary>The same distinction on the way out: an unusable public key never becomes a container error.</summary>
    [Fact]
    public async Task AnUnusablePublicKeyPemPropagatesUnwrapped()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);

        // As above: invalid Base64 became an ArgumentException in Enigma.Core 1.1.0 (BouncyCastle 2.7.0),
        // where 1.0.0 (BouncyCastle 2.6.2) let a raw FormatException escape. §9 permits both.
        ArgumentException malformed = await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.EncryptToBytesAsync(
                "-----BEGIN PUBLIC KEY-----\nnot base64!!\n-----END PUBLIC KEY-----\n", plaintext));

        Assert.Equal("publicKeyPem", malformed.ParamName);
        Assert.NotNull(RsaTestData.FirstFormatException(malformed));

        // A private-key PEM where a public one belongs, and whitespace that our own emptiness check lets
        // through — both are Enigma.Core's to reject.
        foreach (string pem in new[] { keys.PrivateKeyPem, "   " })
        {
            ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
                () => RsaTestData.EncryptToBytesAsync(pem, plaintext));

            Assert.Equal("publicKeyPem", exception.ParamName);
        }
    }

    /// <summary>An unusable public key leaves the output stream untouched — the wrap precedes every write.</summary>
    [Fact]
    public async Task AnUnusablePublicKeyPemWritesNothing()
    {
        using MemoryStream input = new(RsaTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, RsaTestData.NotAPem,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(0, output.Length);
    }

    // --- A tampered payload -------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task AFlippedPayloadBitIsADecryptionError(Cipher cipher)
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem, RsaTestData.Plaintext(256), cipher);

        byte[] tampered = FormatTestData.WithFlippedBit(container, RsaTestData.HeaderLength2048 * 8);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, tampered));
    }

    /// <summary>Anywhere in the payload, including the GCM tag that closes it.</summary>
    [Fact]
    public async Task AFlippedBitAnywhereInThePayloadIsADecryptionError()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(200));

        foreach (int offset in new[]
                 {
                     RsaTestData.HeaderLength2048,        // first ciphertext byte
                     RsaTestData.HeaderLength2048 + 100,  // the middle of the ciphertext
                     container.Length - 17,               // last ciphertext byte
                     container.Length - 16,               // first byte of the GCM tag
                     container.Length - 1,                // last byte of the GCM tag
                 })
        {
            byte[] tampered = FormatTestData.WithFlippedBit(container, offset * 8);

            await Assert.ThrowsAsync<DataDecryptionException>(
                () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, tampered));
        }
    }

    [Fact]
    public async Task ATruncatedOrExtendedPayloadIsADecryptionError()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(200));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container[..^8]));

        // The payload removed entirely: the GCM tag is gone, so authentication cannot succeed.
        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container[..RsaTestData.HeaderLength2048]));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, [.. container, 0x00]));
    }

    // --- An edited header ---------------------------------------------------------------------------

    /// <summary>
    /// Every named field of the header, edited in turn. The outcome is always one of the two documented
    /// exceptions: <see cref="DataEncryptionFormatException"/> where the edit makes the header structurally
    /// invalid, <see cref="DataDecryptionException"/> where it stays parseable and the OAEP unwrap, the
    /// key-confirmation tag or the GCM AAD catches it.
    /// </summary>
    [Theory]
    [MemberData(nameof(HeaderFields))]
    public async Task EditingAnyHeaderFieldIsDetected(string field, int offset)
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(128));
        byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

        DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));

        Assert.True(
            exception is DataEncryptionFormatException or DataDecryptionException,
            $"Editing the {field} at offset {offset} raised {exception.GetType().Name}.");
    }

    /// <summary>And every byte of the header, not only the fields a hand-written list happens to name.</summary>
    [Fact]
    public async Task EditingAnyHeaderByteIsDetected()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        for (int offset = 0; offset < RsaTestData.HeaderLength2048; offset++)
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
                () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));

            Assert.True(
                exception is DataEncryptionFormatException or DataDecryptionException,
                $"Flipping a bit at header offset {offset} raised {exception.GetType().Name}.");
        }
    }

    /// <summary>The structural fields are format errors specifically, not merely "some" error.</summary>
    [Fact]
    public async Task EditingTheMagicOrTheVersionIsAFormatError()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        foreach (int offset in new[] { 0, 1, 3 })
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));
        }
    }

    /// <summary>
    /// Editing the cipher byte to <b>another valid cipher</b> is the interesting case: the header still
    /// parses and the wrapped key is intact, so what catches it is the key-confirmation tag — the header is
    /// covered by it (§6).
    /// </summary>
    [Fact]
    public async Task EditingTheCipherByteToAnotherValidCipherIsADecryptionError()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem, RsaTestData.Plaintext(64), Cipher.Aes256Gcm);

        byte[] edited = FormatTestData.WithByteAt(container, 4, (byte)Cipher.Serpent256Gcm);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));
    }

    [Fact]
    public async Task EditingTheCipherByteToAnUndefinedValueIsAFormatError()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        foreach (byte cipherByte in new byte[] { 0x00, 0x05, 0xFF })
        {
            byte[] edited = FormatTestData.WithByteAt(container, 4, cipherByte);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));
        }
    }

    // --- An edited OAEP-hash byte -------------------------------------------------------------------

    /// <summary>
    /// Editing the hash byte to <b>another accepted hash</b> needs no rule of its own
    /// (<c>docs/format.md</c> §3.3): the reader uses the byte to choose the unwrap, so a wrong value makes
    /// OAEP fail, and §9 already maps that to <see cref="DataDecryptionException"/> with the cause inside.
    /// That is asserted here rather than special-cased in the reader.
    /// </summary>
    [Theory]
    [MemberData(nameof(OaepHashEdits))]
    public async Task EditingTheHashByteToAnotherAcceptedHashIsADecryptionError(
        RsaOaepHash written,
        byte editedTo)
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem, RsaTestData.Plaintext(128), oaepHash: written);

        byte[] edited = FormatTestData.WithByteAt(container, RsaTestData.OaepHashOffset, editedTo);

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));

        Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
    }

    /// <summary>Each accepted hash paired with each of the other two accepted wire bytes.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<RsaOaepHash, byte> OaepHashEdits() => new()
    {
        { RsaOaepHash.Sha256, 0x03 },
        { RsaOaepHash.Sha256, 0x04 },
        { RsaOaepHash.Sha384, 0x02 },
        { RsaOaepHash.Sha384, 0x04 },
        { RsaOaepHash.Sha512, 0x02 },
        { RsaOaepHash.Sha512, 0x03 },
    };

    /// <summary>
    /// Editing it to <c>0x00</c>, the reserved SHA-1 byte, or anything undefined is a format error — the
    /// reader rejects the value before it reaches any key operation.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x01)]
    [InlineData(0x05)]
    [InlineData(0x7F)]
    [InlineData(0xFF)]
    public async Task EditingTheHashByteToAnInvalidValueIsAFormatError(byte hashByte)
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(128));
        byte[] edited = FormatTestData.WithByteAt(container, RsaTestData.OaepHashOffset, hashByte);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));
    }

    /// <summary>
    /// An invalid hash byte is rejected before a payload byte is read, like every other structural field —
    /// so the reserved SHA-1 byte costs a reader nothing.
    /// </summary>
    [Fact]
    public async Task AnInvalidHashByteIsRejectedBeforeThePayloadIsRead()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(4_096));
        byte[] header = FormatTestData.WithByteAt(
            container[..RsaTestData.HeaderLength2048], RsaTestData.OaepHashOffset, RsaOaepHashWire.Sha1Byte);

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.Service().DecryptAsync(
                input, output, keys.PrivateKeyPem,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(input.PayloadWasRead);
        Assert.Equal(0, output.Length);
    }

    // --- A public key too small for the selected hash ------------------------------------------------

    /// <summary>
    /// A modulus too small to wrap 32 bytes under the selected hash is the caller's public key being
    /// unusable, so it is an <see cref="ArgumentException"/> on <c>publicKeyPem</c> with Enigma.Core's
    /// <see cref="CryptographicException"/> preserved inside — the new row of <c>docs/format.md</c> §9.
    /// RSA-1024 is 128 bytes, and SHA-384 needs 130.
    /// </summary>
    [Theory]
    [InlineData(RsaOaepHash.Sha384)]
    [InlineData(RsaOaepHash.Sha512)]
    public async Task ATooSmallPublicKeyIsAnArgumentErrorOnThePublicKey(RsaOaepHash oaepHash)
    {
        ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.EncryptToBytesAsync(
                keys.PublicKeyPem1024, RsaTestData.Plaintext(64), oaepHash: oaepHash));

        Assert.Equal("publicKeyPem", exception.ParamName);
        Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
    }

    /// <summary>
    /// <b>The same gap under the default hash.</b> This was reachable before the hash became selectable —
    /// SHA-256 needs a 98-byte modulus, so a 512-bit key already failed — and Enigma.Core's exception
    /// escaped unwrapped and undocumented. The row covers it now, so it is asserted here too.
    /// </summary>
    [Fact]
    public async Task ATooSmallPublicKeyIsAnArgumentErrorUnderTheDefaultHashToo()
    {
        ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem512, RsaTestData.Plaintext(64)));

        Assert.Equal("publicKeyPem", exception.ParamName);
        Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
    }

    /// <summary>
    /// RSA-1024 still works under SHA-256, which is what makes the two tests above about the hash rather
    /// than about the key being rejected outright.
    /// </summary>
    [Fact]
    public async Task RsaTenTwentyFourStillWorksUnderTheDefaultHash()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);

        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem1024, plaintext);

        Assert.Equal(RsaTestData.HeaderLength(128) + plaintext.Length + 16, container.Length);
        Assert.Equal(plaintext, await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem1024, container));
    }

    /// <summary>A rejected wrap leaves the output stream untouched — the wrap precedes every write.</summary>
    [Fact]
    public async Task ATooSmallPublicKeyWritesNothing()
    {
        using MemoryStream input = new(RsaTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => RsaTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, keys.PublicKeyPem1024, RsaOaepHash.Sha512,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(0, output.Length);
    }

    /// <summary>
    /// Handing another method's container to the RSA service is a format error, not a misparse — each
    /// service reads only its own method byte (<c>docs/format.md</c> §2.2) — and the same holds in reverse.
    /// </summary>
    [Fact]
    public async Task AnotherMethodsContainerIsAFormatError()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);
        byte[] rsaContainer = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext);
        byte[] pbkdf2Container = await PasswordTestData.EncryptToBytesAsync(
            PasswordServiceAdapter.Create(PasswordMethod.Pbkdf2), plaintext);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, pbkdf2Container));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => PasswordTestData.DecryptToBytesAsync(
                PasswordServiceAdapter.Create(PasswordMethod.Pbkdf2), rsaContainer));
    }

    [Fact]
    public async Task AnEmptyOrTinyStreamIsAFormatError()
    {
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, []));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, [0xEC]));
    }

    /// <summary>A header cut short anywhere is a format error, at every offset.</summary>
    [Fact]
    public async Task ATruncatedHeaderIsAFormatErrorAtEveryOffset()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        for (int length = 0; length < RsaTestData.HeaderLength2048; length++)
        {
            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container[..length]));
        }
    }

    // --- The wrapped-key length field ---------------------------------------------------------------

    /// <summary>
    /// The length field at one over its cap, at zero, negative, and at both extremes of
    /// <see cref="int"/> — rejected as a format error, and <b>with no private-key operation attempted</b>:
    /// the service is wired with an RSA factory that throws if it is ever reached.
    /// </summary>
    /// <remarks>
    /// This is what the limits are for (<c>docs/format.md</c> §8). <see cref="int.MaxValue"/> is the pointed
    /// case — a claim of 2 GiB, which must cost a comparison to reject rather than an allocation to
    /// survive.
    /// </remarks>
    [Fact]
    public async Task AWrappedKeyLengthOutOfBoundsIsAFormatErrorWithNoUnwrap()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));
        RsaDataEncryptionService reader = RsaTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory());

        foreach (int value in new[]
                 {
                     DataEncryptionLimits.Default.MaxWrappedKeyLength + 1, 0, -1, int.MinValue, int.MaxValue,
                 })
        {
            byte[] edited = FormatTestData.WithInt32At(container, RsaTestData.WrappedKeyLengthOffset, value);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited, service: reader));
        }
    }

    /// <summary>A zero-length wrapped key is named by the field name that rejected it.</summary>
    [Fact]
    public async Task AZeroWrappedKeyLengthNamesTheField()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));
        byte[] edited = FormatTestData.WithInt32At(container, RsaTestData.WrappedKeyLengthOffset, 0);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));

        Assert.Contains("RSA wrapped-key length", exception.Message);
    }

    /// <summary>
    /// A length that is within the cap but longer than the stream can satisfy: the stream ends inside the
    /// header, which is a format error too.
    /// </summary>
    [Fact]
    public async Task AWrappedKeyLengthBeyondTheEndOfTheStreamIsAFormatError()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));

        foreach (int value in new[] { 1_024, DataEncryptionLimits.Default.MaxWrappedKeyLength })
        {
            byte[] edited = FormatTestData.WithInt32At(container, RsaTestData.WrappedKeyLengthOffset, value);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, edited));
        }
    }

    /// <summary>
    /// Tightened limits are honoured: a container written with a legal wrapped-key length is refused by a
    /// reader whose bound is stricter than the header's value — and refused before the private key is used.
    /// </summary>
    [Fact]
    public async Task TightenedLimitsRejectAnOtherwiseValidHeader()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(64));
        DataEncryptionLimits strict = new() { MaxWrappedKeyLength = RsaTestData.WrappedKeyLength2048 - 1 };

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.DecryptToBytesAsync(
                keys.PrivateKeyPem,
                container,
                limits: strict,
                service: RsaTestData.Service(publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory())));
    }

    /// <summary>A limit exactly at the wrapped-key length is legal — the cap includes its own value.</summary>
    [Fact]
    public async Task ALimitExactlyAtTheWrappedKeyLengthIsAccepted()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext);
        DataEncryptionLimits atCap = new() { MaxWrappedKeyLength = RsaTestData.WrappedKeyLength2048 };

        Assert.Equal(
            plaintext,
            await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container, limits: atCap));
    }

    /// <summary>And the default limits accept what the service itself writes, at every key size.</summary>
    [Fact]
    public async Task TheDefaultLimitsAcceptTheServicesOwnOutput()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);

        foreach ((string publicKeyPem, string privateKeyPem) in new[]
                 {
                     (keys.PublicKeyPem, keys.PrivateKeyPem),
                     (keys.PublicKeyPem3072, keys.PrivateKeyPem3072),
                     (keys.PublicKeyPem4096, keys.PrivateKeyPem4096),
                 })
        {
            byte[] container = await RsaTestData.EncryptToBytesAsync(publicKeyPem, plaintext);

            Assert.Equal(
                plaintext,
                await RsaTestData.DecryptToBytesAsync(
                    privateKeyPem, container, limits: DataEncryptionLimits.Default));
        }
    }

    /// <summary>
    /// Nothing above ever surfaces an exception type the contract does not name — no
    /// <see cref="NullReferenceException"/>, no indexing failure, no unwrapped Enigma.Core exception.
    /// </summary>
    /// <remarks>
    /// The systematic sweep across all four methods lives in PHASE05; this is the RSA slice of it, so a
    /// regression here is caught in the phase that introduced it. The credential is valid throughout, so
    /// only container errors are admissible outcomes.
    /// </remarks>
    [Fact]
    public async Task NoCorruptionEverEscapesTheDocumentedExceptionTypes()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, RsaTestData.Plaintext(32));

        List<byte[]> corrupted = [];
        for (int offset = 0; offset < container.Length; offset++)
        {
            corrupted.Add(FormatTestData.WithByteAt(container, offset, 0x00));
            corrupted.Add(FormatTestData.WithByteAt(container, offset, 0xFF));
        }

        for (int length = 0; length <= container.Length; length++)
        {
            corrupted.Add(container[..length]);
        }

        foreach (byte[] candidate in corrupted)
        {
            try
            {
                await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, candidate);
            }
            catch (DataEncryptionFormatException)
            {
                // Documented.
            }
            catch (DataDecryptionException)
            {
                // Documented.
            }
        }
    }
}
