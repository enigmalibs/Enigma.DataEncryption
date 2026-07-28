using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Golden vectors for method <c>0x04</c>, in both directions: the exact bytes the service must write for fixed
/// inputs, and committed container files it must read back to an exact plaintext.
/// </summary>
/// <remarks>
/// <para>
/// <b>The encapsulation is the one thing that cannot be pinned on the write path, and it is pinned around
/// rather than ignored.</b> ML-KEM encapsulation draws its own randomness inside Enigma.Core, so two calls
/// against the same public key produce different ciphertexts <i>and</i> different shared secrets — and the
/// encapsulation is 1,568 of the 1024-bit container's 1,667 bytes. Everything else is asserted byte-for-byte:
/// the 22-byte header prefix, the length field, the key-confirmation tag, and the whole payload. Where the
/// encapsulation is needed to rebuild the rest, it is taken from the container under test and its secret
/// recovered with Enigma.Core's KEM — so the assertion is "given this encapsulation, every other byte is
/// exactly this", which is the strongest statement available for a randomized primitive.
/// </para>
/// <para>
/// <b>The read path has no such limitation, and is pinned completely.</b> The committed fixtures include the
/// key pair <i>and</i> the shared secret the committed encapsulation yields, so
/// <see cref="TheCommittedEncapsulationYieldsTheCommittedSecret"/> pins the KEM itself, and everything
/// downstream of it is a fixed byte sequence. This mirrors Enigma.Core's own
/// <c>kem1024_A_private.key</c> / <c>encapsulation.bin</c> / <c>secret.bin</c> fixture style.
/// </para>
/// <para>
/// <b>The expectations are independent of this library.</b> The committed fixtures were generated from
/// <c>docs/format.md</c> §3.4 with Enigma.Core's ML-KEM and the platform's HMAC-SHA256 and
/// <see cref="System.Security.Cryptography.AesGcm"/>, and the tests below rebuild them from platform
/// primitives at run time, so the independence is re-established on every run rather than asserted in a
/// comment. As in PHASE02 and PHASE03, the Twofish payload is a <i>regression</i> vector — no Twofish-GCM
/// implementation exists outside BouncyCastle here — while its header remains independent.
/// </para>
/// <para>
/// The inputs: the committed ML-KEM-1024 and ML-KEM-512 key pairs, nonce <c>00</c>–<c>0B</c>, and the 45-byte
/// plaintext in <c>Services/Fixtures/golden-plaintext.txt</c>.
/// </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public sealed class MLKemGoldenVectorTests
{
    /// <summary>The committed containers, with the cipher and parameter set each was written under.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string, string, Cipher, MLKemParameterSet> Fixtures() => new()
    {
        { "mlkem-1024-aes.bin", "1024", Cipher.Aes256Gcm, MLKemParameterSet.MLKem1024 },
        { "mlkem-1024-twofish.bin", "1024", Cipher.Twofish256Gcm, MLKemParameterSet.MLKem1024 },
        { "mlkem-512-aes.bin", "512", Cipher.Aes256Gcm, MLKemParameterSet.MLKem512 },
    };

    /// <summary>The committed key pairs, by fixture slug.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string, MLKemParameterSet> KeyPairs() => new()
    {
        { "1024", MLKemParameterSet.MLKem1024 },
        { "512", MLKemParameterSet.MLKem512 },
    };

    // --- The committed key material -----------------------------------------------------------------

    /// <summary>
    /// The committed keys are the lengths FIPS 203 fixes for their parameter set — the first thing that would
    /// break if a fixture file were ever regenerated against the wrong set.
    /// </summary>
    [Theory]
    [MemberData(nameof(KeyPairs))]
    public void TheCommittedKeysHaveTheSpecifiedLengths(string slug, MLKemParameterSet parameterSet)
    {
        (int publicLength, int privateLength) = parameterSet switch
        {
            MLKemParameterSet.MLKem512 => (800, 1_632),
            MLKemParameterSet.MLKem768 => (1_184, 2_400),
            _ => (1_568, 3_168),
        };

        Assert.Equal(publicLength, MLKemTestData.GoldenPublicKey(slug).Length);
        Assert.Equal(privateLength, MLKemTestData.GoldenPrivateKey(slug).Length);
        Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, MLKemTestData.GoldenSecret(slug).Length);
    }

    /// <summary>
    /// The KEM itself is pinned: the encapsulation carried by the committed container, decapsulated with the
    /// committed private key, yields exactly the committed shared secret. Everything else in this suite treats
    /// that secret as a known quantity, so it is established here first — with Enigma.Core's KEM directly,
    /// never through the service under test.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void TheCommittedEncapsulationYieldsTheCommittedSecret(
        string fixture,
        string slug,
        Cipher cipher,
        MLKemParameterSet parameterSet)
    {
        _ = cipher;
        byte[] encapsulation = MLKemTestData.EncapsulationOf(
            MLKemTestData.Fixture(fixture), MLKemTestData.EncapsulationLengthOf(parameterSet));

        Assert.Equal(
            MLKemTestData.GoldenSecret(slug),
            MLKemTestData.Decapsulate(encapsulation, MLKemTestData.GoldenPrivateKey(slug), parameterSet));
    }

    // --- The committed containers -------------------------------------------------------------------

    /// <summary>The header layout of the committed fixture is exactly what §3.4 tabulates.</summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void TheCommittedFixtureHasTheSpecifiedLayout(
        string fixture,
        string slug,
        Cipher cipher,
        MLKemParameterSet parameterSet)
    {
        _ = slug;
        byte[] container = MLKemTestData.Fixture(fixture);
        int n = MLKemTestData.EncapsulationLengthOf(parameterSet);

        Assert.Equal<byte[]>([0xEC, 0xDE], container[..2]);
        Assert.Equal((byte)EncryptionMethod.MLKem, container[2]);
        Assert.Equal(0x10, container[3]);
        Assert.Equal((byte)cipher, container[4]);
        Assert.Equal(MLKemTestData.WireByteOf(parameterSet), container[MLKemTestData.ParameterSetOffset]);
        Assert.Equal(
            FormatTestData.Nonce(),
            container[MLKemTestData.NonceOffset..MLKemTestData.EncapsulationLengthOffset]);
        Assert.Equal(
            MLKemTestData.LittleEndian(n),
            container[MLKemTestData.EncapsulationLengthOffset..MLKemTestData.EncapsulationOffset]);
        Assert.Equal(
            MLKemTestData.HeaderLength(n) + MLKemTestData.GoldenPlaintext().Length + 16,
            container.Length);
    }

    /// <summary>
    /// The 1024 fixtures are 1,667 bytes and the 512 fixture 867 — the arithmetic of §3.4 written out, so a
    /// change to any field size shows up as a number rather than a shrug.
    /// </summary>
    [Fact]
    public void TheCommittedFixtureLengthsAreTheArithmeticOfTheSpecification()
    {
        Assert.Equal(1_606, MLKemTestData.HeaderLengthOf(MLKemParameterSet.MLKem1024));
        Assert.Equal(806, MLKemTestData.HeaderLengthOf(MLKemParameterSet.MLKem512));

        Assert.Equal(1_667, MLKemTestData.Fixture("mlkem-1024-aes.bin").Length);
        Assert.Equal(1_667, MLKemTestData.Fixture("mlkem-1024-twofish.bin").Length);
        Assert.Equal(867, MLKemTestData.Fixture("mlkem-512-aes.bin").Length);
    }

    /// <summary>
    /// The committed container rebuilt from the platform's own primitives, taking only its encapsulation bytes
    /// from the file. No library code contributes to the expectation, so agreement means the format is right
    /// rather than self-consistent.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public void TheCommittedFixtureIsWhatTheIndependentPrimitivesProduce(
        string fixture,
        string slug,
        Cipher cipher,
        MLKemParameterSet parameterSet)
    {
        byte[] container = MLKemTestData.Fixture(fixture);
        int n = MLKemTestData.EncapsulationLengthOf(parameterSet);
        byte[] secret = MLKemTestData.GoldenSecret(slug);
        byte[] header = IndependentHeader(
            cipher, parameterSet, MLKemTestData.EncapsulationOf(container, n), secret);

        Assert.Equal(header, container[..MLKemTestData.HeaderLength(n)]);

        // The payload can only be rebuilt independently where the platform has the cipher: AES-GCM. The
        // Twofish fixture's payload is a regression vector, pinned by the round-trip and by this header.
        if (cipher == Cipher.Aes256Gcm)
        {
            Assert.Equal(
                GoldenVectorPrimitives.AesGcmPayload(
                    secret, FormatTestData.Nonce(), header, MLKemTestData.GoldenPlaintext()),
                container[MLKemTestData.HeaderLength(n)..]);
        }
    }

    // --- Read path ----------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Fixtures))]
    public async Task TheCommittedFixtureDecryptsToTheExpectedPlaintext(
        string fixture,
        string slug,
        Cipher cipher,
        MLKemParameterSet parameterSet)
    {
        _ = cipher;
        _ = parameterSet;

        Assert.Equal(
            MLKemTestData.GoldenPlaintext(),
            await MLKemTestData.DecryptToBytesAsync(
                MLKemTestData.GoldenPrivateKey(slug), MLKemTestData.Fixture(fixture)));
    }

    /// <summary>
    /// A fixture opened with an unrelated key of the same parameter set fails — the case FIPS 203 implicit
    /// rejection lets decapsulate successfully, so this is the key-confirmation tag earning its place on real
    /// committed bytes rather than on a container the test just built.
    /// </summary>
    [Theory]
    [MemberData(nameof(KeyPairs))]
    public async Task TheCommittedFixtureRejectsAnUnrelatedKey(string slug, MLKemParameterSet parameterSet)
    {
        (_, byte[] unrelatedPrivateKey) =
            new MLKemServiceFactory().CreateMLKemService(parameterSet).GenerateKeyPair();
        string fixture = slug == "1024" ? "mlkem-1024-aes.bin" : "mlkem-512-aes.bin";

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(unrelatedPrivateKey, MLKemTestData.Fixture(fixture)));

        Assert.Contains("key-confirmation tag", exception.Message);
    }

    /// <summary>The committed key pair is a pair: what the public key encapsulates against, the private key opens.</summary>
    [Theory]
    [MemberData(nameof(KeyPairs))]
    public async Task TheCommittedKeyPairRoundTripsAFreshContainer(string slug, MLKemParameterSet parameterSet)
    {
        byte[] plaintext = MLKemTestData.Plaintext(200);

        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            MLKemTestData.GoldenPublicKey(slug), plaintext, Cipher.Aes256Gcm, parameterSet);

        Assert.Equal(
            plaintext,
            await MLKemTestData.DecryptToBytesAsync(MLKemTestData.GoldenPrivateKey(slug), container));
    }

    // --- Write path ---------------------------------------------------------------------------------

    /// <summary>
    /// The write path, pinned byte-for-byte except the encapsulation: given the nonce, the header prefix, the
    /// length field, the key-confirmation tag and the whole payload are all exactly what the specification and
    /// the platform's primitives say they should be.
    /// </summary>
    [Theory]
    [MemberData(nameof(Fixtures))]
    public async Task TheWritePathIsByteExactExceptTheEncapsulation(
        string fixture,
        string slug,
        Cipher cipher,
        MLKemParameterSet parameterSet)
    {
        byte[] produced = await WriteGoldenContainerAsync(slug, cipher, parameterSet);
        byte[] committed = MLKemTestData.Fixture(fixture);
        int n = MLKemTestData.EncapsulationLengthOf(parameterSet);

        // Everything up to the encapsulation is fixed, and identical to the committed fixture.
        Assert.Equal(
            committed[..MLKemTestData.EncapsulationOffset], produced[..MLKemTestData.EncapsulationOffset]);
        Assert.Equal(committed.Length, produced.Length);

        // The encapsulation is not — that is the KEM's randomness, not a defect — and neither, therefore, is
        // the shared secret. Everything downstream of it is rebuilt from the bytes actually produced.
        byte[] encapsulation = MLKemTestData.EncapsulationOf(produced, n);
        Assert.NotEqual(MLKemTestData.EncapsulationOf(committed, n), encapsulation);

        byte[] secret = MLKemTestData.Decapsulate(
            encapsulation, MLKemTestData.GoldenPrivateKey(slug), parameterSet);
        Assert.NotEqual(MLKemTestData.GoldenSecret(slug), secret);

        byte[] header = IndependentHeader(cipher, parameterSet, encapsulation, secret);
        Assert.Equal(header, produced[..MLKemTestData.HeaderLength(n)]);

        if (cipher == Cipher.Aes256Gcm)
        {
            Assert.Equal(
                GoldenVectorPrimitives.AesGcmPayload(
                    secret, FormatTestData.Nonce(), header, MLKemTestData.GoldenPlaintext()),
                produced[MLKemTestData.HeaderLength(n)..]);
        }

        // And it opens with the committed private key, so the encapsulation encapsulates what it claims to.
        Assert.Equal(
            MLKemTestData.GoldenPlaintext(),
            await MLKemTestData.DecryptToBytesAsync(MLKemTestData.GoldenPrivateKey(slug), produced));
    }

    /// <summary>
    /// Two encapsulations against the same public key differ, and both open — the property that makes a full
    /// byte-for-byte write vector impossible in the first place, and the reason the shared secret cannot be a
    /// fixed constant the way the password methods' data key is.
    /// </summary>
    [Fact]
    public async Task TheEncapsulationIsFreshEvenWithAFixedNonce()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024;
        const int n = MLKemTestData.EncapsulationLength1024;

        byte[] first = await WriteGoldenContainerAsync("1024", Cipher.Aes256Gcm, parameterSet);
        byte[] second = await WriteGoldenContainerAsync("1024", Cipher.Aes256Gcm, parameterSet);

        Assert.Equal(
            first[..MLKemTestData.EncapsulationOffset], second[..MLKemTestData.EncapsulationOffset]);
        Assert.NotEqual(MLKemTestData.EncapsulationOf(first, n), MLKemTestData.EncapsulationOf(second, n));

        // The key-confirmation tag covers the encapsulation, so it differs too — and so, through the AAD,
        // does the payload.
        Assert.NotEqual(
            first[MLKemTestData.KeyConfirmationTagOffset(n)..],
            second[MLKemTestData.KeyConfirmationTagOffset(n)..]);

        foreach (byte[] container in new[] { first, second })
        {
            Assert.Equal(
                MLKemTestData.GoldenPlaintext(),
                await MLKemTestData.DecryptToBytesAsync(MLKemTestData.GoldenPrivateKey("1024"), container));
        }
    }

    /// <summary>
    /// The header bytes of §3.4, laid out by hand from the specification and tagged with the platform's
    /// HMAC-SHA256. Note the parameter-set byte between the cipher and the nonce, and that it is the wire
    /// value rather than the enum's.
    /// </summary>
    private static byte[] IndependentHeader(
        Cipher cipher,
        MLKemParameterSet parameterSet,
        byte[] encapsulation,
        byte[] sharedSecret)
    {
        byte[] headerBeforeTag =
        [
            0xEC, 0xDE, 0x04, 0x10, (byte)cipher, MLKemTestData.WireByteOf(parameterSet),
            .. FormatTestData.Nonce(),
            .. MLKemTestData.LittleEndian(encapsulation.Length),
            .. encapsulation,
        ];
        Assert.Equal(MLKemTestData.KeyConfirmationTagOffset(encapsulation.Length), headerBeforeTag.Length);

        return
        [
            .. headerBeforeTag,
            .. GoldenVectorPrimitives.KeyConfirmationTag(sharedSecret, headerBeforeTag),
        ];
    }

    private static async Task<byte[]> WriteGoldenContainerAsync(
        string slug,
        Cipher cipher,
        MLKemParameterSet parameterSet)
    {
        using MemoryStream input = new(MLKemTestData.GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await MLKemTestData.Deterministic().EncryptAsync(
            input,
            output,
            cipher,
            MLKemTestData.GoldenPublicKey(slug),
            parameterSet,
            null,
            TestContext.Current.CancellationToken);

        return output.ToArray();
    }
}
