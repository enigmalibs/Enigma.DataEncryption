using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Round-trips the RSA method across every cipher, every key size and every payload shape, and asserts the
/// stream-level promises the XML docs make: nothing is disposed, nothing needs to be seekable, and progress
/// counts payload bytes only.
/// </summary>
/// <remarks>
/// The variable-length wrapped key is what makes RSA different from the password methods, so the header
/// shape is asserted at all three key sizes: <c>N</c> is the modulus size in bytes, and the header is
/// 38 + <c>N</c> long (<c>docs/format.md</c> §3.3). <c>N</c> does <b>not</b> depend on the OAEP hash,
/// which is why the cipher × hash sweep below can assert one length for all three.
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(RsaKeyCollection.Name)]
public sealed class RsaRoundTripTests(RsaKeyFixture keys)
{
    /// <summary>All four ciphers.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher> Ciphers() => [.. RsaTestData.AllCiphers];

    /// <summary>The three key sizes, with the wrapped-key length each produces.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<int, int> KeySizes() =>
        new() { { 2048, 256 }, { 3072, 384 }, { 4096, 512 } };

    /// <summary>Every cipher crossed with every accepted OAEP hash — twelve combinations.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher, RsaOaepHash> CiphersAndOaepHashes()
    {
        TheoryData<Cipher, RsaOaepHash> data = [];
        foreach (Cipher cipher in RsaTestData.AllCiphers)
        {
            foreach (RsaOaepHash oaepHash in RsaTestData.AllOaepHashes)
            {
                data.Add(cipher, oaepHash);
            }
        }

        return data;
    }

    /// <summary>The three accepted OAEP hashes, with the wire byte each records at offset 5.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<RsaOaepHash, byte> OaepHashesAndWireBytes() =>
        new() { { RsaOaepHash.Sha256, 0x02 }, { RsaOaepHash.Sha384, 0x03 }, { RsaOaepHash.Sha512, 0x04 } };

    // --- The OAEP hash ------------------------------------------------------------------------------

    /// <summary>
    /// The acceptance criterion: all four ciphers round-trip under all three hashes, and the header is the
    /// same length either way — the hash changes the padding, not the ciphertext size.
    /// </summary>
    [Theory]
    [MemberData(nameof(CiphersAndOaepHashes))]
    public async Task RoundTripsEveryCipherUnderEveryOaepHash(Cipher cipher, RsaOaepHash oaepHash)
    {
        byte[] plaintext = RsaTestData.Plaintext(1_024 + 7);

        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem, plaintext, cipher, oaepHash: oaepHash);

        Assert.Equal(RsaTestData.HeaderLength2048 + plaintext.Length + 16, container.Length);
        Assert.Equal(plaintext, await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container));
    }

    /// <summary>
    /// RSA-3072 too, so the hash and the modulus size are shown to be independent axes rather than a pair
    /// that happens to work at 2048.
    /// </summary>
    [Theory]
    [MemberData(nameof(OaepHashesAndWireBytes))]
    public async Task RoundTripsAtRsa3072UnderEveryOaepHash(RsaOaepHash oaepHash, byte expectedWireByte)
    {
        byte[] plaintext = RsaTestData.Plaintext(300);

        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem3072, plaintext, oaepHash: oaepHash);

        Assert.Equal(expectedWireByte, container[RsaTestData.OaepHashOffset]);
        Assert.Equal(RsaTestData.HeaderLength(384) + plaintext.Length + 16, container.Length);
        Assert.Equal(plaintext, await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem3072, container));
    }

    /// <summary>The selected hash is what lands at offset 5 (<c>docs/format.md</c> §3.3).</summary>
    [Theory]
    [MemberData(nameof(OaepHashesAndWireBytes))]
    public async Task TheSelectedHashIsRecordedAtOffsetFive(RsaOaepHash oaepHash, byte expectedWireByte)
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem, RsaTestData.Plaintext(64), oaepHash: oaepHash);

        Assert.Equal(expectedWireByte, container[RsaTestData.OaepHashOffset]);
    }

    /// <summary>
    /// Omitting the parameter selects SHA-256 — the documented default, and the byte a container written by
    /// a caller who never heard of this field carries.
    /// </summary>
    [Fact]
    public async Task TheDefaultHashIsSha256()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);
        RsaDataEncryptionService service = RsaTestData.Service();

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await service.EncryptAsync(
            input, output, Cipher.Aes256Gcm, keys.PublicKeyPem,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(0x02, output.ToArray()[RsaTestData.OaepHashOffset]);
    }

    /// <summary>
    /// The wrapped key really is OAEP under the hash the header names: unwrapping with that hash recovers
    /// the data key the confirmation tag was computed under, and the other two hashes do not.
    /// </summary>
    [Theory]
    [MemberData(nameof(OaepHashesAndWireBytes))]
    public async Task TheWrappedKeyUnwrapsOnlyUnderTheRecordedHash(RsaOaepHash oaepHash, byte wireByte)
    {
        FixedDataKeyAndNonceSource randomSource = new(FormatTestData.DataKey(), FormatTestData.Nonce());

        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem,
            RsaTestData.Plaintext(16),
            service: RsaTestData.Service(randomSource),
            oaepHash: oaepHash);

        byte[] wrappedKey = RsaTestData.WrappedKeyOf(container);
        Assert.Equal(wireByte, container[RsaTestData.OaepHashOffset]);
        Assert.Equal(
            FormatTestData.DataKey(),
            RsaTestData.UnwrapOaep(wrappedKey, keys.PrivateKeyPem, oaepHash: oaepHash));

        foreach (RsaOaepHash other in RsaTestData.AllOaepHashes)
        {
            if (other == oaepHash) continue;

            Assert.ThrowsAny<CryptographicException>(
                () => RsaTestData.UnwrapOaep(wrappedKey, keys.PrivateKeyPem, oaepHash: other));
        }
    }

    /// <summary>
    /// The header is still the GCM associated data in full, hash byte included: flipping offset 5 on a
    /// finished container cannot be tolerated by any path.
    /// </summary>
    [Fact]
    public async Task TheHashByteIsCoveredByTheAssociatedData()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem, RsaTestData.Plaintext(128), oaepHash: RsaOaepHash.Sha384);

        byte[] tampered = FormatTestData.WithByteAt(container, RsaTestData.OaepHashOffset, 0x04);

        await Assert.ThrowsAnyAsync<DataEncryptionException>(
            () => RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, tampered));
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task RoundTripsExactly(Cipher cipher)
    {
        byte[] plaintext = RsaTestData.Plaintext(4_096 + 17);

        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext, cipher);
        byte[] recovered = await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container);

        Assert.Equal(plaintext, recovered);
    }

    /// <summary>
    /// The container is exactly the header, the ciphertext and the 128-bit GCM tag — no padding, no
    /// trailer (<c>docs/format.md</c> §4).
    /// </summary>
    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task TheContainerIsHeaderPlusCiphertextPlusTag(Cipher cipher)
    {
        byte[] plaintext = RsaTestData.Plaintext(1_000);

        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext, cipher);

        Assert.Equal(RsaTestData.HeaderLength2048 + plaintext.Length + 16, container.Length);
        Assert.Equal((byte)EncryptionMethod.Rsa, container[2]);
        Assert.Equal(DataEncryptionDefaults.FormatVersion, container[3]);
        Assert.Equal((byte)cipher, container[4]);
    }

    /// <summary>
    /// 2048, 3072 and 4096 all work, and the wrapped-key length field says the modulus size — the field the
    /// whole variable-length shape hangs on.
    /// </summary>
    [Theory]
    [MemberData(nameof(KeySizes))]
    public async Task RoundTripsAtEveryKeySize(int keySizeBits, int expectedWrappedKeyLength)
    {
        (string publicKeyPem, string privateKeyPem) = KeyPairOf(keySizeBits);
        byte[] plaintext = RsaTestData.Plaintext(300);

        byte[] container = await RsaTestData.EncryptToBytesAsync(publicKeyPem, plaintext);

        Assert.Equal(
            RsaTestData.LittleEndian(expectedWrappedKeyLength),
            container[RsaTestData.WrappedKeyLengthOffset..RsaTestData.WrappedKeyOffset]);
        Assert.Equal(
            RsaTestData.HeaderLength(expectedWrappedKeyLength) + plaintext.Length + 16,
            container.Length);

        Assert.Equal(plaintext, await RsaTestData.DecryptToBytesAsync(privateKeyPem, container));
    }

    [Fact]
    public async Task RoundTripsAnEmptyPayload()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, []);
        Assert.Equal(RsaTestData.HeaderLength2048 + 16, container.Length);

        Assert.Empty(await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container));
    }

    [Fact]
    public async Task RoundTripsASinglePayloadByte()
    {
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, [0x5A]);

        Assert.Equal<byte[]>([0x5A], await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container));
    }

    // --- Large payload, and evidence that it streams -------------------------------------------------

    /// <summary>
    /// An 8 MiB payload, generated rather than materialized, round-tripped and verified byte by byte as it
    /// arrives — the RSA operation covers the 32-byte data key only, so file size is unconstrained by the
    /// key size.
    /// </summary>
    [Fact]
    public async Task RoundTripsALargePayload()
    {
        const int size = 8 * 1024 * 1024;
        RsaDataEncryptionService service = RsaTestData.Service();

        using PatternStream plaintext = new(size);
        using MemoryStream container = new();
        await service.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
            TestContext.Current.CancellationToken);

        Assert.Equal(RsaTestData.HeaderLength2048 + size + 16, container.Length);

        container.Position = 0;
        using PatternVerifyingStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken);

        Assert.Equal(size, recovered.BytesWritten);
    }

    /// <summary>
    /// The payload is streamed, not buffered: ciphertext reaches the output while the input still has bytes
    /// left to give.
    /// </summary>
    [Fact]
    public async Task StreamsRatherThanBufferingTheWholePayload()
    {
        const int size = 8 * 1024 * 1024;

        using PatternStream plaintext = new(size);
        long readWhenFirstPayloadByteWasWritten = -1;
        using CountingSink container = new(
            RsaTestData.HeaderLength2048, () => readWhenFirstPayloadByteWasWritten = plaintext.BytesRead);

        await RsaTestData.Service().EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
            TestContext.Current.CancellationToken);

        Assert.True(
            readWhenFirstPayloadByteWasWritten is > 0 and < size,
            $"The first payload write happened after {readWhenFirstPayloadByteWasWritten} of {size} input bytes had been read; a streaming implementation writes before the input is exhausted.");
    }

    // --- Stream contract ----------------------------------------------------------------------------

    /// <summary>Decryption must not require a seekable stream (<c>docs/format.md</c> §7.2).</summary>
    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task DecryptsFromANonSeekableDripFedStream(Cipher cipher)
    {
        byte[] plaintext = RsaTestData.Plaintext(300);
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext, cipher);

        // A chunk size that is not a divisor of the header length, so the wrapped key is delivered across
        // read boundaries — the tee-ed AAD has to survive that.
        using ForwardOnlyStream input = new(container, maxChunk: 7);
        using MemoryStream output = new();
        await RsaTestData.Service().DecryptAsync(
            input, output, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, output.ToArray());
    }

    /// <summary>Neither stream is disposed, and the caller's position is left where the operation ended.</summary>
    [Fact]
    public async Task NeitherStreamIsDisposed()
    {
        RsaDataEncryptionService service = RsaTestData.Service();
        byte[] plaintext = RsaTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
            TestContext.Current.CancellationToken);

        // A disposed MemoryStream throws on these; a live one does not.
        Assert.True(input.CanRead);
        Assert.True(container.CanWrite);
        Assert.Equal(container.Length, container.Position);

        container.Position = 0;
        using MemoryStream output = new();
        await service.DecryptAsync(
            container, output, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken);

        Assert.True(container.CanRead);
        Assert.True(output.CanWrite);
    }

    /// <summary>
    /// The container is written at the output stream's current position, not at its start — so a caller may
    /// prepend their own framing.
    /// </summary>
    [Fact]
    public async Task WritesAtTheOutputStreamsCurrentPosition()
    {
        byte[] preamble = [0xDE, 0xAD, 0xBE, 0xEF];
        RsaDataEncryptionService service = RsaTestData.Service();
        byte[] plaintext = RsaTestData.Plaintext(48);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await output.WriteAsync(preamble, 0, preamble.Length, TestContext.Current.CancellationToken);
        await service.EncryptAsync(
            input, output, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, null,
            TestContext.Current.CancellationToken);

        byte[] written = output.ToArray();
        Assert.Equal(preamble, written[..4]);
        Assert.Equal(0xEC, written[4]);

        output.Position = preamble.Length;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            output, recovered, keys.PrivateKeyPem, null, null, null, TestContext.Current.CancellationToken);
        Assert.Equal(plaintext, recovered.ToArray());
    }

    // --- Progress -----------------------------------------------------------------------------------

    /// <summary>
    /// Progress totals the payload byte count and excludes the header, on both directions. Were the
    /// 294-byte header counted, the sums below would be larger by exactly that.
    /// </summary>
    [Fact]
    public async Task ProgressTotalsThePayloadBytesAndExcludesTheHeader()
    {
        const int size = 10_000;
        RsaDataEncryptionService service = RsaTestData.Service();
        byte[] plaintext = RsaTestData.Plaintext(size);

        ProgressCollector encryptProgress = new();
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.PublicKeyPem, RsaOaepHash.Sha256, encryptProgress,
            TestContext.Current.CancellationToken);

        Assert.NotEmpty(encryptProgress.Values);
        Assert.All(encryptProgress.Values, value => Assert.True(value > 0, $"Progress reported {value}."));
        Assert.Equal(size, encryptProgress.Total);

        ProgressCollector decryptProgress = new();
        container.Position = 0;
        using MemoryStream output = new();
        await service.DecryptAsync(
            container, output, keys.PrivateKeyPem, null, null, decryptProgress, TestContext.Current.CancellationToken);

        Assert.NotEmpty(decryptProgress.Values);
        Assert.All(decryptProgress.Values, value => Assert.True(value > 0, $"Progress reported {value}."));
        Assert.Equal(size, decryptProgress.Total);
    }

    // --- The data key and the nonce -----------------------------------------------------------------

    /// <summary>
    /// A fresh data key and nonce per call: two encryptions of the same plaintext under the same public key
    /// must not produce the same container. Nonce reuse under one key is the classic GCM catastrophe, and
    /// here the key is freshly generated too.
    /// </summary>
    [Fact]
    public async Task EachCallDrawsAFreshDataKeyAndNonce()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);

        byte[] first = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext);
        byte[] second = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext);

        Assert.NotEqual(first, second);
        Assert.NotEqual(first[6..18], second[6..18]);                                        // nonce
        Assert.NotEqual(RsaTestData.WrappedKeyOf(first), RsaTestData.WrappedKeyOf(second));  // wrapped key
    }

    /// <summary>The data key and nonce come from the injected source, one of each, at the specified sizes.</summary>
    [Fact]
    public async Task TheDataKeyAndNonceComeFromTheRandomSource()
    {
        FixedDataKeyAndNonceSource randomSource = new(FormatTestData.DataKey(), FormatTestData.Nonce());

        byte[] container = await RsaTestData.EncryptToBytesAsync(
            keys.PublicKeyPem, RsaTestData.Plaintext(16), service: RsaTestData.Service(randomSource));

        Assert.Equal(FormatTestData.Nonce(), container[6..18]);
        Assert.Equal(1, randomSource.Requests[DataEncryptionDefaults.DataKeySizeBytes]);
        Assert.Equal(1, randomSource.Requests[DataEncryptionDefaults.NonceSizeBytes]);

        // …and the wrapped key really wraps the data key the source handed out.
        Assert.Equal(
            FormatTestData.DataKey(),
            RsaTestData.UnwrapOaep(RsaTestData.WrappedKeyOf(container), keys.PrivateKeyPem));
    }

    // --- An encrypted private-key PEM ---------------------------------------------------------------

    /// <summary>
    /// A passphrase-protected private key opens a container written for its public half, and the caller's
    /// passphrase array survives the call untouched — the XML docs promise the caller owns its lifetime.
    /// </summary>
    [Fact]
    public async Task AnEncryptedPrivateKeyPemOpensTheContainer()
    {
        byte[] plaintext = RsaTestData.Plaintext(256);
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.EncryptedPemPublicKeyPem, plaintext);
        char[] passphrase = keys.PemPassphraseChars();

        byte[] recovered = await RsaTestData.DecryptToBytesAsync(
            keys.EncryptedPrivateKeyPem, container, passphrase);

        Assert.Equal(plaintext, recovered);
        Assert.Equal(keys.PemPassphraseChars(), passphrase);
    }

    /// <summary>An unencrypted PEM is unbothered by a passphrase it does not need.</summary>
    [Fact]
    public async Task AnUnencryptedPemIgnoresASuppliedPassphrase()
    {
        byte[] plaintext = RsaTestData.Plaintext(64);
        byte[] container = await RsaTestData.EncryptToBytesAsync(keys.PublicKeyPem, plaintext);

        Assert.Equal(
            plaintext,
            await RsaTestData.DecryptToBytesAsync(keys.PrivateKeyPem, container, keys.PemPassphraseChars()));
    }

    private (string PublicKeyPem, string PrivateKeyPem) KeyPairOf(int keySizeBits) => keySizeBits switch
    {
        2048 => (keys.PublicKeyPem, keys.PrivateKeyPem),
        3072 => (keys.PublicKeyPem3072, keys.PrivateKeyPem3072),
        _ => (keys.PublicKeyPem4096, keys.PrivateKeyPem4096),
    };
}
