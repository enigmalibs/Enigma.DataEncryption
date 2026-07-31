using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Golden vectors for method <c>0x03</c>, in both directions: the exact bytes the service must write for
/// fixed inputs, and committed container files it must read back to an exact plaintext.
/// </summary>
/// <remarks>
/// <para>
/// <b>The wrapped key is the one thing that cannot be pinned, and it is pinned around rather than
/// ignored.</b> RSAES-OAEP draws fresh randomness inside its padding, so two wraps of the same data key
/// under the same public key differ — and the wrapped key is 256 of the container's 355 bytes. Everything
/// else is asserted byte-for-byte: the 22-byte header prefix (the OAEP-hash byte included), the
/// wrapped-key length field, the key-confirmation tag computed over the produced header, and the whole
/// payload. Where the wrapped-key bytes are needed to rebuild the rest, they are taken from the container
/// under test — so the assertion is "given these wrapped-key bytes, every other byte is exactly this",
/// which is the strongest statement available for a randomized primitive.
/// </para>
/// <para>
/// <b>Each accepted OAEP hash has its own committed container.</b> The hash is a header field
/// (<c>docs/format.md</c> §3.3), so a vector pinning only the default would leave two thirds of the field's
/// range unpinned on the read path. The three AES fixtures differ in exactly one plaintext header byte and
/// in the wrapped key; their payloads differ too, because the header is the AAD.
/// </para>
/// <para>
/// <b>The expectations are independent of this library.</b> The committed fixtures were generated from
/// <c>docs/format.md</c> §3.3 with Enigma.Core's RSA and the platform's HMAC-SHA256 and
/// <see cref="System.Security.Cryptography.AesGcm"/>, and
/// <see cref="TheCommittedFixtureIsWhatTheIndependentPrimitivesProduce"/> rebuilds them from platform
/// primitives at run time, so the independence is re-established on every run rather than asserted in a
/// comment. As in PHASE02, the Twofish payload is a <i>regression</i> vector — no Twofish-GCM
/// implementation exists outside BouncyCastle here — while its header remains independent.
/// </para>
/// <para>
/// The inputs: the committed RSA-2048 key pair, data key <c>00</c>–<c>1F</c>, nonce <c>00</c>–<c>0B</c>,
/// and the 45-byte plaintext in <c>Services/Fixtures/golden-plaintext.txt</c>.
/// </para>
/// </remarks>
public sealed class RsaGoldenVectorTests
{
    /// <summary>The committed containers, by cipher byte and OAEP hash.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string, Cipher, RsaOaepHash> Fixtures() => new()
    {
        { "rsa-aes.bin", Cipher.Aes256Gcm, RsaOaepHash.Sha256 },
        { "rsa-twofish.bin", Cipher.Twofish256Gcm, RsaOaepHash.Sha256 },
        { "rsa-aes-sha384.bin", Cipher.Aes256Gcm, RsaOaepHash.Sha384 },
        { "rsa-aes-sha512.bin", Cipher.Aes256Gcm, RsaOaepHash.Sha512 },
    };

    /// <summary>The committed containers, for the assertions that do not care which cipher.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string> FixtureNames() =>
        ["rsa-aes.bin", "rsa-twofish.bin", "rsa-aes-sha384.bin", "rsa-aes-sha512.bin"];

    /// <summary>The committed containers whose wrapped key was produced under a given hash.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string, RsaOaepHash> FixturesByOaepHash() => new()
    {
        { "rsa-aes.bin", RsaOaepHash.Sha256 },
        { "rsa-twofish.bin", RsaOaepHash.Sha256 },
        { "rsa-aes-sha384.bin", RsaOaepHash.Sha384 },
        { "rsa-aes-sha512.bin", RsaOaepHash.Sha512 },
    };

    // --- The committed containers -------------------------------------------------------------------

    /// <summary>The header layout of the committed fixture is exactly what §3.3 tabulates.</summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void TheCommittedFixtureHasTheSpecifiedLayout(string fixture, Cipher cipher, RsaOaepHash oaepHash)
    {
        byte[] container = RsaTestData.Fixture(fixture);

        Assert.Equal(355, container.Length);
        Assert.Equal<byte[]>([0xEC, 0xDE], container[..2]);
        Assert.Equal((byte)EncryptionMethod.Rsa, container[2]);
        Assert.Equal(0x10, container[3]);
        Assert.Equal((byte)cipher, container[4]);
        Assert.Equal(RsaOaepHashWire.ToWireByte(oaepHash), container[RsaTestData.OaepHashOffset]);
        Assert.Equal(
            FormatTestData.Nonce(),
            container[RsaTestData.NonceOffset..RsaTestData.WrappedKeyLengthOffset]);
        Assert.Equal(
            RsaTestData.LittleEndian(RsaTestData.WrappedKeyLength2048),
            container[RsaTestData.WrappedKeyLengthOffset..RsaTestData.WrappedKeyOffset]);
        Assert.Equal(294, RsaTestData.HeaderLength2048);
        Assert.Equal(
            RsaTestData.HeaderLength2048 + RsaTestData.GoldenPlaintext().Length + 16,
            container.Length);
    }

    /// <summary>
    /// The three AES fixtures differ in exactly the offset-5 byte among the first 22, which is what makes
    /// them a vector for <i>the field</i> rather than three unrelated containers.
    /// </summary>
    [Fact]
    public void TheThreeAesFixturesDifferOnlyInTheOaepHashByteBeforeTheWrappedKey()
    {
        byte[] sha256 = RsaTestData.Fixture("rsa-aes.bin");
        byte[] sha384 = RsaTestData.Fixture("rsa-aes-sha384.bin");
        byte[] sha512 = RsaTestData.Fixture("rsa-aes-sha512.bin");

        foreach ((byte[] other, byte expected) in new[] { (sha384, (byte)0x03), (sha512, (byte)0x04) })
        {
            Assert.Equal(0x02, sha256[RsaTestData.OaepHashOffset]);
            Assert.Equal(expected, other[RsaTestData.OaepHashOffset]);

            Assert.Equal(sha256[..RsaTestData.OaepHashOffset], other[..RsaTestData.OaepHashOffset]);
            Assert.Equal(
                sha256[(RsaTestData.OaepHashOffset + 1)..RsaTestData.WrappedKeyOffset],
                other[(RsaTestData.OaepHashOffset + 1)..RsaTestData.WrappedKeyOffset]);

            // …and the payload differs, because the header is the AAD (§5).
            Assert.NotEqual(
                sha256[RsaTestData.HeaderLength2048..],
                other[RsaTestData.HeaderLength2048..]);
        }
    }

    /// <summary>
    /// The fixture's wrapped key really wraps the documented data key — checked with Enigma.Core's OAEP
    /// directly, so the rest of this suite may treat <c>00</c>–<c>1F</c> as a known quantity.
    /// </summary>
    [Theory]
    [MemberData(nameof(FixturesByOaepHash))]
    public void TheCommittedFixtureWrapsTheDocumentedDataKey(string fixture, RsaOaepHash oaepHash)
    {
        byte[] wrappedKey = RsaTestData.WrappedKeyOf(RsaTestData.Fixture(fixture));

        Assert.Equal(
            FormatTestData.DataKey(),
            RsaTestData.UnwrapOaep(wrappedKey, RsaTestData.GoldenPrivateKeyPem(), oaepHash: oaepHash));
    }

    /// <summary>
    /// The committed container rebuilt from the platform's own primitives, taking only its wrapped-key
    /// bytes from the file. No library code contributes to the expectation, so agreement means the format
    /// is right rather than self-consistent.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void TheCommittedFixtureIsWhatTheIndependentPrimitivesProduce(
        string fixture,
        Cipher cipher,
        RsaOaepHash oaepHash)
    {
        byte[] container = RsaTestData.Fixture(fixture);
        byte[] dataKey = FormatTestData.DataKey();
        byte[] header = IndependentHeader(cipher, oaepHash, RsaTestData.WrappedKeyOf(container), dataKey);

        Assert.Equal(header, container[..RsaTestData.HeaderLength2048]);

        // The payload can only be rebuilt independently where the platform has the cipher: AES-GCM. The
        // Twofish fixture's payload is a regression vector, pinned by the round-trip and by this header.
        if (cipher == Cipher.Aes256Gcm)
        {
            Assert.Equal(
                GoldenVectorPrimitives.AesGcmPayload(
                    dataKey, FormatTestData.Nonce(), header, RsaTestData.GoldenPlaintext()),
                container[RsaTestData.HeaderLength2048..]);
        }
    }

    // --- Read path ----------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(FixtureNames))]
    public async Task TheCommittedFixtureDecryptsToTheExpectedPlaintext(string fixture)
    {
        Assert.Equal(
            RsaTestData.GoldenPlaintext(),
            await RsaTestData.DecryptToBytesAsync(
                RsaTestData.GoldenPrivateKeyPem(), RsaTestData.Fixture(fixture)));
    }

    /// <summary>
    /// The same container, opened with the same key supplied as a passphrase-protected PKCS#8 PEM — the
    /// credential form a caller is most likely to have on disk.
    /// </summary>
    [Fact]
    public async Task TheCommittedFixtureOpensWithTheEncryptedPrivateKeyPem()
    {
        char[] passphrase = RsaTestData.GoldenPemPassphraseChars();

        byte[] recovered = await RsaTestData.DecryptToBytesAsync(
            RsaTestData.GoldenEncryptedPrivateKeyPem(), RsaTestData.Fixture("rsa-aes.bin"), passphrase);

        Assert.Equal(RsaTestData.GoldenPlaintext(), recovered);
        Assert.Equal(RsaTestData.GoldenPemPassphraseChars(), passphrase);
    }

    /// <summary>A fixture opened with an unrelated key fails, as it would in the field.</summary>
    [Fact]
    public async Task TheCommittedFixtureRejectsAnUnrelatedKey()
    {
        (_, string unrelatedPrivateKeyPem) =
            new Core.Asymmetric.PublicKey.PublicKeyServiceFactory().CreatePublicKeyService()
                .GenerateRsaKeyPair(2048);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => RsaTestData.DecryptToBytesAsync(unrelatedPrivateKeyPem, RsaTestData.Fixture("rsa-aes.bin")));
    }

    /// <summary>The committed key pair is a pair: what the public key wraps, the private key opens.</summary>
    [Fact]
    public async Task TheCommittedKeyPairRoundTripsAFreshContainer()
    {
        byte[] plaintext = RsaTestData.Plaintext(200);

        byte[] container = await RsaTestData.EncryptToBytesAsync(RsaTestData.GoldenPublicKeyPem(), plaintext);

        Assert.Equal(
            plaintext,
            await RsaTestData.DecryptToBytesAsync(RsaTestData.GoldenPrivateKeyPem(), container));
    }

    // --- Write path ---------------------------------------------------------------------------------

    /// <summary>
    /// The write path, pinned byte-for-byte except the wrapped key: given the data key and nonce, the
    /// header prefix, the length field, the key-confirmation tag and the whole payload are all exactly what
    /// the specification and the platform's primitives say they should be.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public async Task TheWritePathIsByteExactExceptTheWrappedKey(
        string fixture,
        Cipher cipher,
        RsaOaepHash oaepHash)
    {
        byte[] produced = await WriteGoldenContainerAsync(cipher, oaepHash);
        byte[] committed = RsaTestData.Fixture(fixture);
        byte[] dataKey = FormatTestData.DataKey();

        // Everything up to the wrapped key is fixed, and identical to the committed fixture.
        Assert.Equal(committed[..RsaTestData.WrappedKeyOffset], produced[..RsaTestData.WrappedKeyOffset]);
        Assert.Equal(committed.Length, produced.Length);

        // The wrapped key is not — that is OAEP's randomness, not a defect. Everything downstream of it is
        // rebuilt from the bytes actually produced.
        byte[] wrappedKey = RsaTestData.WrappedKeyOf(produced);
        Assert.NotEqual(RsaTestData.WrappedKeyOf(committed), wrappedKey);

        byte[] header = IndependentHeader(cipher, oaepHash, wrappedKey, dataKey);
        Assert.Equal(header, produced[..RsaTestData.HeaderLength2048]);

        if (cipher == Cipher.Aes256Gcm)
        {
            Assert.Equal(
                GoldenVectorPrimitives.AesGcmPayload(
                    dataKey, FormatTestData.Nonce(), header, RsaTestData.GoldenPlaintext()),
                produced[RsaTestData.HeaderLength2048..]);
        }

        // And it opens with the committed private key, so the wrapped key wraps what it claims to.
        Assert.Equal(
            RsaTestData.GoldenPlaintext(),
            await RsaTestData.DecryptToBytesAsync(RsaTestData.GoldenPrivateKeyPem(), produced));
    }

    /// <summary>
    /// Two wraps of the same data key under the same public key differ, and both open — the property that
    /// makes a full byte-for-byte write vector impossible in the first place.
    /// </summary>
    [Fact]
    public async Task TheWrappedKeyIsFreshEvenWithAFixedDataKeyAndNonce()
    {
        byte[] first = await WriteGoldenContainerAsync(Cipher.Aes256Gcm, RsaOaepHash.Sha256);
        byte[] second = await WriteGoldenContainerAsync(Cipher.Aes256Gcm, RsaOaepHash.Sha256);

        Assert.Equal(first[..RsaTestData.WrappedKeyOffset], second[..RsaTestData.WrappedKeyOffset]);
        Assert.NotEqual(RsaTestData.WrappedKeyOf(first), RsaTestData.WrappedKeyOf(second));

        // The key-confirmation tag covers the wrapped key, so it differs too — and so, through the AAD,
        // does the payload.
        Assert.NotEqual(
            first[RsaTestData.KeyConfirmationTagOffset(RsaTestData.WrappedKeyLength2048)..],
            second[RsaTestData.KeyConfirmationTagOffset(RsaTestData.WrappedKeyLength2048)..]);

        foreach (byte[] container in new[] { first, second })
        {
            Assert.Equal(
                RsaTestData.GoldenPlaintext(),
                await RsaTestData.DecryptToBytesAsync(RsaTestData.GoldenPrivateKeyPem(), container));
        }
    }

    /// <summary>
    /// The header bytes of §3.3, laid out by hand from the specification and tagged with the platform's
    /// HMAC-SHA256.
    /// </summary>
    /// <remarks>
    /// The OAEP-hash byte is written out as the literal the specification tabulates, not taken from
    /// <c>RsaOaepHashWire</c>: an expectation built from the mapping under test would assert nothing about
    /// which byte §3.3 actually commits to.
    /// </remarks>
    private static byte[] IndependentHeader(
        Cipher cipher,
        RsaOaepHash oaepHash,
        byte[] wrappedKey,
        byte[] dataKey)
    {
        byte oaepHashByte = oaepHash switch
        {
            RsaOaepHash.Sha256 => 0x02,
            RsaOaepHash.Sha384 => 0x03,
            RsaOaepHash.Sha512 => 0x04,
            _ => throw new Xunit.Sdk.XunitException($"§3.3 assigns no wire byte to {oaepHash}."),
        };

        byte[] headerBeforeTag =
        [
            0xEC, 0xDE, 0x03, 0x10, (byte)cipher,
            oaepHashByte,
            .. FormatTestData.Nonce(),
            .. RsaTestData.LittleEndian(wrappedKey.Length),
            .. wrappedKey,
        ];
        Assert.Equal(RsaTestData.KeyConfirmationTagOffset(wrappedKey.Length), headerBeforeTag.Length);

        return [.. headerBeforeTag, .. GoldenVectorPrimitives.KeyConfirmationTag(dataKey, headerBeforeTag)];
    }

    private static async Task<byte[]> WriteGoldenContainerAsync(Cipher cipher, RsaOaepHash oaepHash)
    {
        using MemoryStream input = new(RsaTestData.GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await RsaTestData.Deterministic().EncryptAsync(
            input, output, cipher, RsaTestData.GoldenPublicKeyPem(), oaepHash, null,
            TestContext.Current.CancellationToken);

        return output.ToArray();
    }
}
