using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Golden vectors for method <c>0x05</c>, in both directions: the exact bytes the service must write for
/// fixed inputs, and committed container files it must read back to an exact plaintext.
/// </summary>
/// <remarks>
/// <para>
/// <b>This method has two randomized fields where the others have one, and both are pinned around rather
/// than ignored.</b> RSAES-OAEP draws fresh randomness inside its padding, and ML-KEM encapsulation draws its
/// own inside Enigma.Core, so two calls against the same key pair differ in the wrapped secret, in the
/// encapsulation, <i>and</i> — because the data key is combined from both — in the key-confirmation tag and
/// the whole payload. Between them the two ciphertexts are 1,824 of the container's 1,927 bytes. Everything
/// else is asserted byte-for-byte, and where the ciphertexts are needed to rebuild the rest they are taken
/// from the container under test, so the assertion is "given these two ciphertexts, every other byte is
/// exactly this" — the strongest statement available for two randomized primitives.
/// </para>
/// <para>
/// <b>The read path has no such limitation and is pinned completely.</b> The committed fixtures include both
/// key pairs and the ML-KEM shared secret the committed encapsulation yields, so the KEM is pinned as a
/// constant, the RSA half's secret is the documented <c>00</c>–<c>1F</c>, and the combined data key is
/// therefore a fixed value that <see cref="TheCommittedFixtureCombinesToTheExpectedDataKey"/> reconstructs.
/// </para>
/// <para>
/// <b>The expectations are independent of this library.</b> The header — the combiner included — is rebuilt
/// at run time from the platform's <c>HMACSHA256</c> through
/// <see cref="GoldenVectorPrimitives.HybridDataKey"/> and
/// <see cref="GoldenVectorPrimitives.KeyConfirmationTag"/>, which share no code with
/// <c>HybridKeyCombiner</c> or <c>KeyConfirmation</c>. As in the other methods' suites the Twofish payload is
/// a <i>regression</i> vector — no Twofish-GCM implementation exists outside BouncyCastle here — while its
/// header remains independent.
/// </para>
/// <para>
/// The inputs: the committed RSA-2048 key pair and ML-KEM-1024 key pair, RSA-half secret <c>00</c>–<c>1F</c>,
/// nonce <c>00</c>–<c>0B</c>, and the 45-byte plaintext in <c>Services/Fixtures/golden-plaintext.txt</c>.
/// Both committed containers share one wrapped secret and one encapsulation, so they differ only in their
/// cipher byte, tag and payload — which is what lets a single committed KEM secret pin both.
/// </para>
/// </remarks>
public sealed class HybridGoldenVectorTests
{
    private const MLKemParameterSet Golden = MLKemParameterSet.MLKem1024;
    private const int N = HybridTestData.WrappedSecretLength2048;
    private const int M = MLKemTestData.EncapsulationLength1024;

    /// <summary>The committed containers, by cipher byte.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string, Cipher> Fixtures() => new()
    {
        { "hybrid-aes.bin", Cipher.Aes256Gcm },
        { "hybrid-twofish.bin", Cipher.Twofish256Gcm },
    };

    /// <summary>The committed containers, for the assertions that do not care which cipher.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string> FixtureNames() => ["hybrid-aes.bin", "hybrid-twofish.bin"];

    // --- The committed containers -------------------------------------------------------------------

    /// <summary>The header layout of the committed fixture is exactly what §3.5 tabulates.</summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void TheCommittedFixtureHasTheSpecifiedLayout(string fixture, Cipher cipher)
    {
        byte[] container = HybridTestData.Fixture(fixture);

        Assert.Equal(1_927, container.Length);
        Assert.Equal<byte[]>([0xEC, 0xDE], container[..2]);
        Assert.Equal((byte)EncryptionMethod.Hybrid, container[2]);
        Assert.Equal(0x10, container[3]);
        Assert.Equal((byte)cipher, container[4]);

        // ML-KEM-1024 — wire byte 0x03, not the enum's 2.
        Assert.Equal(0x03, container[HybridTestData.ParameterSetOffset]);
        Assert.Equal(
            FormatTestData.Nonce(),
            container[HybridTestData.NonceOffset..HybridTestData.WrappedSecretLengthOffset]);

        Assert.Equal(
            HybridTestData.LittleEndian(N),
            container[HybridTestData.WrappedSecretLengthOffset..HybridTestData.WrappedSecretOffset]);

        int encapsulationLengthOffset = HybridTestData.EncapsulationLengthOffset(N);
        Assert.Equal(
            HybridTestData.LittleEndian(M),
            container[encapsulationLengthOffset..(encapsulationLengthOffset + 4)]);

        Assert.Equal(1_866, HybridTestData.HeaderLength(N, M));
        Assert.Equal(
            HybridTestData.HeaderLength(N, M) + HybridTestData.GoldenPlaintext().Length + 16,
            container.Length);
    }

    /// <summary>
    /// The arithmetic of §3.5 written out, so a change to any field size shows up as a number rather than a
    /// shrug.
    /// </summary>
    [Fact]
    public void TheCommittedFixtureLengthsAreTheArithmeticOfTheSpecification()
    {
        Assert.Equal(1_866, HybridTestData.HeaderLengthOf(MLKemParameterSet.MLKem1024));
        Assert.Equal(1_386, HybridTestData.HeaderLengthOf(MLKemParameterSet.MLKem768));
        Assert.Equal(1_066, HybridTestData.HeaderLengthOf(MLKemParameterSet.MLKem512));

        Assert.Equal(1_927, HybridTestData.Fixture("hybrid-aes.bin").Length);
        Assert.Equal(1_927, HybridTestData.Fixture("hybrid-twofish.bin").Length);
    }

    /// <summary>
    /// The fixture's RSAES-OAEP ciphertext really wraps the documented <c>00</c>–<c>1F</c> — checked with
    /// Enigma.Core's OAEP directly, so the rest of this suite may treat it as a known quantity.
    /// </summary>
    [Theory]
    [MemberData(nameof(FixtureNames))]
    public void TheCommittedFixtureWrapsTheDocumentedRsaSecret(string fixture)
    {
        byte[] wrapped = HybridTestData.WrappedSecretOf(HybridTestData.Fixture(fixture));

        Assert.Equal(
            FormatTestData.DataKey(),
            HybridTestData.UnwrapOaep(wrapped, HybridTestData.GoldenRsaPrivateKeyPem()));
    }

    /// <summary>
    /// The KEM half is pinned too: the encapsulation carried by the committed container, decapsulated with
    /// the committed private key, yields exactly the committed shared secret — with Enigma.Core's KEM
    /// directly, never through the service under test.
    /// </summary>
    [Theory]
    [MemberData(nameof(FixtureNames))]
    public void TheCommittedEncapsulationYieldsTheCommittedKemSecret(string fixture)
    {
        byte[] encapsulation = HybridTestData.EncapsulationOf(HybridTestData.Fixture(fixture), M);

        Assert.Equal(
            HybridTestData.GoldenKemSecret(),
            HybridTestData.Decapsulate(
                encapsulation, HybridTestData.GoldenMLKemPrivateKey("1024"), Golden));
    }

    /// <summary>
    /// Both fixtures carry the <b>same</b> two ciphertexts, so the one committed KEM secret pins both — and
    /// they differ from each other only in the cipher byte, the tag and the payload.
    /// </summary>
    [Fact]
    public void TheTwoCommittedFixturesShareTheirCiphertexts()
    {
        byte[] aes = HybridTestData.Fixture("hybrid-aes.bin");
        byte[] twofish = HybridTestData.Fixture("hybrid-twofish.bin");

        Assert.Equal(HybridTestData.WrappedSecretOf(aes), HybridTestData.WrappedSecretOf(twofish));
        Assert.Equal(
            HybridTestData.EncapsulationOf(aes, M), HybridTestData.EncapsulationOf(twofish, M));

        // Only the cipher byte differs in the header prefix...
        Assert.Equal((byte)Cipher.Aes256Gcm, aes[4]);
        Assert.Equal((byte)Cipher.Twofish256Gcm, twofish[4]);
        Assert.Equal(aes[..4], twofish[..4]);
        Assert.Equal(aes[5..HybridTestData.WrappedSecretOffset], twofish[5..HybridTestData.WrappedSecretOffset]);

        // ...and, because the cipher byte is covered by the tag and the tag by the AAD, everything from the
        // tag onwards differs.
        int tagOffset = HybridTestData.KeyConfirmationTagOffset(N, M);
        Assert.NotEqual(aes[tagOffset..], twofish[tagOffset..]);
    }

    /// <summary>
    /// <b>The combiner, pinned on committed bytes.</b> Both input secrets are known constants here — the RSA
    /// half is <c>00</c>–<c>1F</c> and the KEM half is the committed secret — so the data key the container
    /// was written under is a fixed value, and it is reconstructed from the platform's HMAC rather than from
    /// this library's combiner.
    /// </summary>
    [Theory]
    [MemberData(nameof(FixtureNames))]
    public void TheCommittedFixtureCombinesToTheExpectedDataKey(string fixture)
    {
        byte[] container = HybridTestData.Fixture(fixture);
        byte[] wrapped = HybridTestData.WrappedSecretOf(container);
        byte[] encapsulation = HybridTestData.EncapsulationOf(container, M);

        byte[] independent = GoldenVectorPrimitives.HybridDataKey(
            FormatTestData.DataKey(), HybridTestData.GoldenKemSecret(), wrapped, encapsulation);

        // The library's own combiner agrees with the independent one on the committed bytes.
        Assert.Equal(
            independent,
            HybridTestData.Combine(
                FormatTestData.DataKey(), HybridTestData.GoldenKemSecret(), wrapped, encapsulation));

        // And the header's key-confirmation tag is the tag over that combined key — which is what ties the
        // committed container to the combiner rather than merely to a 32-byte value.
        int tagOffset = HybridTestData.KeyConfirmationTagOffset(N, M);
        Assert.Equal(
            GoldenVectorPrimitives.KeyConfirmationTag(independent, container[..tagOffset]),
            container[tagOffset..HybridTestData.HeaderLength(N, M)]);
    }

    /// <summary>
    /// The committed container rebuilt from the platform's own primitives, taking only its two ciphertexts
    /// from the file. No library code contributes to the expectation, so agreement means the format is right
    /// rather than self-consistent.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void TheCommittedFixtureIsWhatTheIndependentPrimitivesProduce(string fixture, Cipher cipher)
    {
        byte[] container = HybridTestData.Fixture(fixture);
        byte[] wrapped = HybridTestData.WrappedSecretOf(container);
        byte[] encapsulation = HybridTestData.EncapsulationOf(container, M);
        byte[] dataKey = GoldenVectorPrimitives.HybridDataKey(
            FormatTestData.DataKey(), HybridTestData.GoldenKemSecret(), wrapped, encapsulation);

        byte[] header = IndependentHeader(cipher, wrapped, encapsulation, dataKey);

        Assert.Equal(header, container[..HybridTestData.HeaderLength(N, M)]);

        // The payload can only be rebuilt independently where the platform has the cipher: AES-GCM. The
        // Twofish fixture's payload is a regression vector, pinned by the round-trip and by this header.
        if (cipher == Cipher.Aes256Gcm)
        {
            Assert.Equal(
                GoldenVectorPrimitives.AesGcmPayload(
                    dataKey, FormatTestData.Nonce(), header, HybridTestData.GoldenPlaintext()),
                container[HybridTestData.HeaderLength(N, M)..]);
        }
    }

    // --- Read path ----------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(FixtureNames))]
    public async Task TheCommittedFixtureDecryptsToTheExpectedPlaintext(string fixture)
    {
        Assert.Equal(
            HybridTestData.GoldenPlaintext(),
            await HybridTestData.DecryptToBytesAsync(
                HybridTestData.GoldenRsaPrivateKeyPem(),
                HybridTestData.GoldenMLKemPrivateKey("1024"),
                HybridTestData.Fixture(fixture)));
    }

    /// <summary>
    /// The same container, with the RSA half supplied as a passphrase-protected PKCS#8 PEM — the credential
    /// form a caller is most likely to have on disk.
    /// </summary>
    [Fact]
    public async Task TheCommittedFixtureOpensWithTheEncryptedRsaPrivateKeyPem()
    {
        char[] passphrase = HybridTestData.GoldenPemPassphraseChars();

        byte[] recovered = await HybridTestData.DecryptToBytesAsync(
            HybridTestData.GoldenEncryptedRsaPrivateKeyPem(),
            HybridTestData.GoldenMLKemPrivateKey("1024"),
            HybridTestData.Fixture("hybrid-aes.bin"),
            passphrase);

        Assert.Equal(HybridTestData.GoldenPlaintext(), recovered);
        Assert.Equal(HybridTestData.GoldenPemPassphraseChars(), passphrase);
    }

    /// <summary>
    /// A fixture opened with an unrelated key of either kind fails — and the two fail for different reasons,
    /// which is the asymmetry §6.3 describes: OAEP catches the RSA half, the key-confirmation tag catches the
    /// ML-KEM half.
    /// </summary>
    [Fact]
    public async Task TheCommittedFixtureRejectsAnUnrelatedKeyOfEitherKind()
    {
        byte[] container = HybridTestData.Fixture("hybrid-aes.bin");

        (_, string unrelatedRsaPrivateKeyPem) =
            new Core.Asymmetric.PublicKey.PublicKeyServiceFactory().CreatePublicKeyService()
                .GenerateRsaKeyPair(2048);
        (_, byte[] unrelatedMLKemPrivateKey) =
            new MLKemServiceFactory().CreateMLKemService(Golden).GenerateKeyPair();

        DataDecryptionException rsa = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                unrelatedRsaPrivateKeyPem, HybridTestData.GoldenMLKemPrivateKey("1024"), container));
        Assert.Contains("RSA private key", rsa.Message);

        DataDecryptionException kem = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                HybridTestData.GoldenRsaPrivateKeyPem(), unrelatedMLKemPrivateKey, container));
        Assert.Contains("key-confirmation tag", kem.Message);
    }

    /// <summary>Both committed key pairs are pairs: what the public keys protect, the private keys open.</summary>
    [Fact]
    public async Task TheCommittedKeyPairsRoundTripAFreshContainer()
    {
        byte[] plaintext = HybridTestData.Plaintext(200);

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            HybridTestData.GoldenRsaPublicKeyPem(),
            HybridTestData.GoldenMLKemPublicKey("1024"),
            plaintext,
            Cipher.Aes256Gcm,
            Golden);

        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                HybridTestData.GoldenRsaPrivateKeyPem(),
                HybridTestData.GoldenMLKemPrivateKey("1024"),
                container));
    }

    // --- Write path ---------------------------------------------------------------------------------

    /// <summary>
    /// The write path, pinned byte-for-byte except the two ciphertexts: given the nonce and the RSA-half
    /// secret, the header prefix, both length fields, the key-confirmation tag and the whole payload are all
    /// exactly what the specification and the platform's primitives say they should be.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public async Task TheWritePathIsByteExactExceptTheTwoCiphertexts(string fixture, Cipher cipher)
    {
        byte[] produced = await WriteGoldenContainerAsync(cipher);
        byte[] committed = HybridTestData.Fixture(fixture);

        // Everything up to the first ciphertext is fixed, and identical to the committed fixture.
        Assert.Equal(
            committed[..HybridTestData.WrappedSecretOffset], produced[..HybridTestData.WrappedSecretOffset]);
        Assert.Equal(committed.Length, produced.Length);

        // Neither ciphertext is fixed — that is OAEP's and the KEM's randomness, not a defect — and neither,
        // therefore, is the shared secret or the combined data key. Everything downstream is rebuilt from the
        // bytes actually produced.
        byte[] wrapped = HybridTestData.WrappedSecretOf(produced);
        byte[] encapsulation = HybridTestData.EncapsulationOf(produced, M);
        Assert.NotEqual(HybridTestData.WrappedSecretOf(committed), wrapped);
        Assert.NotEqual(HybridTestData.EncapsulationOf(committed, M), encapsulation);

        // The length field between the two ciphertexts is fixed, though.
        int encapsulationLengthOffset = HybridTestData.EncapsulationLengthOffset(N);
        Assert.Equal(
            HybridTestData.LittleEndian(M),
            produced[encapsulationLengthOffset..(encapsulationLengthOffset + 4)]);

        byte[] kemSecret = HybridTestData.Decapsulate(
            encapsulation, HybridTestData.GoldenMLKemPrivateKey("1024"), Golden);
        Assert.NotEqual(HybridTestData.GoldenKemSecret(), kemSecret);

        // The RSA half's secret *is* fixed — it comes from the deterministic random source.
        Assert.Equal(
            FormatTestData.DataKey(),
            HybridTestData.UnwrapOaep(wrapped, HybridTestData.GoldenRsaPrivateKeyPem()));

        byte[] dataKey = GoldenVectorPrimitives.HybridDataKey(
            FormatTestData.DataKey(), kemSecret, wrapped, encapsulation);
        byte[] header = IndependentHeader(cipher, wrapped, encapsulation, dataKey);
        Assert.Equal(header, produced[..HybridTestData.HeaderLength(N, M)]);

        if (cipher == Cipher.Aes256Gcm)
        {
            Assert.Equal(
                GoldenVectorPrimitives.AesGcmPayload(
                    dataKey, FormatTestData.Nonce(), header, HybridTestData.GoldenPlaintext()),
                produced[HybridTestData.HeaderLength(N, M)..]);
        }

        // And it opens with both committed private keys, so the two ciphertexts carry what they claim to.
        Assert.Equal(
            HybridTestData.GoldenPlaintext(),
            await HybridTestData.DecryptToBytesAsync(
                HybridTestData.GoldenRsaPrivateKeyPem(),
                HybridTestData.GoldenMLKemPrivateKey("1024"),
                produced));
    }

    /// <summary>
    /// Two containers written from identical fixed inputs differ in <b>both</b> ciphertexts, and both open —
    /// the property that makes a full byte-for-byte write vector impossible in the first place, and the
    /// reason the combined data key cannot be a fixed constant the way the password methods' data key is.
    /// </summary>
    [Fact]
    public async Task BothCiphertextsAreFreshEvenWithAFixedNonceAndRsaSecret()
    {
        byte[] first = await WriteGoldenContainerAsync(Cipher.Aes256Gcm);
        byte[] second = await WriteGoldenContainerAsync(Cipher.Aes256Gcm);

        Assert.Equal(
            first[..HybridTestData.WrappedSecretOffset], second[..HybridTestData.WrappedSecretOffset]);
        Assert.NotEqual(HybridTestData.WrappedSecretOf(first), HybridTestData.WrappedSecretOf(second));
        Assert.NotEqual(
            HybridTestData.EncapsulationOf(first, M), HybridTestData.EncapsulationOf(second, M));

        // The key-confirmation tag covers both ciphertexts and the data key is combined from both secrets, so
        // the tag differs — and so, through the AAD, does the payload.
        int tagOffset = HybridTestData.KeyConfirmationTagOffset(N, M);
        Assert.NotEqual(first[tagOffset..], second[tagOffset..]);

        foreach (byte[] container in new[] { first, second })
        {
            Assert.Equal(
                HybridTestData.GoldenPlaintext(),
                await HybridTestData.DecryptToBytesAsync(
                    HybridTestData.GoldenRsaPrivateKeyPem(),
                    HybridTestData.GoldenMLKemPrivateKey("1024"),
                    container));
        }
    }

    /// <summary>
    /// The header bytes of §3.5, laid out by hand from the specification and tagged with the platform's
    /// HMAC-SHA256. Note the parameter-set byte between the cipher and the nonce, that it is the wire value
    /// rather than the enum's, and that the second length field sits <i>between</i> the two ciphertexts
    /// rather than beside the first.
    /// </summary>
    private static byte[] IndependentHeader(
        Cipher cipher,
        byte[] wrappedRsaSecret,
        byte[] encapsulation,
        byte[] dataKey)
    {
        byte[] headerBeforeTag =
        [
            0xEC, 0xDE, 0x05, 0x10, (byte)cipher, MLKemTestData.WireByteOf(Golden),
            .. FormatTestData.Nonce(),
            .. HybridTestData.LittleEndian(wrappedRsaSecret.Length), .. wrappedRsaSecret,
            .. HybridTestData.LittleEndian(encapsulation.Length), .. encapsulation,
        ];
        Assert.Equal(
            HybridTestData.KeyConfirmationTagOffset(wrappedRsaSecret.Length, encapsulation.Length),
            headerBeforeTag.Length);

        return
        [
            .. headerBeforeTag,
            .. GoldenVectorPrimitives.KeyConfirmationTag(dataKey, headerBeforeTag),
        ];
    }

    private static async Task<byte[]> WriteGoldenContainerAsync(Cipher cipher)
    {
        using MemoryStream input = new(HybridTestData.GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await HybridTestData.Deterministic().EncryptAsync(
            input,
            output,
            cipher,
            HybridTestData.GoldenRsaPublicKeyPem(),
            HybridTestData.GoldenMLKemPublicKey("1024"),
            Golden,
            null,
            TestContext.Current.CancellationToken);

        return output.ToArray();
    }
}
