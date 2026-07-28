using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Round-trips all five header shapes through <see cref="HeaderWriter"/> and
/// <see cref="HeaderReader"/>, and — the load-bearing assertion — proves the associated data the reader
/// reconstructs is byte-identical to what the writer produced.
/// </summary>
/// <remarks>
/// The AAD identity is what makes GCM's header authentication work at all. The reader tees the bytes it
/// consumes rather than re-serializing the fields it parsed, so any writer/reader asymmetry shows up
/// here as a byte mismatch rather than downstream as an unexplained authentication failure at the end
/// of a payload.
/// </remarks>
public sealed class HeaderRoundTripTests
{
    public static TheoryData<HeaderShape, Cipher> ShapesAndCiphers()
    {
        TheoryData<HeaderShape, Cipher> data = [];
        foreach (HeaderShape shape in FormatTestData.AllShapes)
        {
            foreach (Cipher cipher in new[] { Cipher.Aes256Gcm, Cipher.Twofish256Gcm, Cipher.Serpent256Gcm, Cipher.Camellia256Gcm })
            {
                data.Add(shape, cipher);
            }
        }

        return data;
    }

    /// <summary>Every header shape.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<HeaderShape> Shapes() => [.. FormatTestData.AllShapes];

    [Theory]
    [MemberData(nameof(ShapesAndCiphers))]
    public async Task TheAssociatedDataIsByteIdenticalInBothDirections(HeaderShape shape, Cipher cipher)
    {
        using MemoryStream container = new();
        byte[] written = await FormatTestData.WriteHeaderAsync(container, shape, cipher);
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, FormatTestData.MethodOf(shape), DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(written, parsed.HeaderBytes);
    }

    [Theory]
    [MemberData(nameof(ShapesAndCiphers))]
    public async Task TheAssociatedDataIsExactlyWhatIsOnTheWire(HeaderShape shape, Cipher cipher)
    {
        using MemoryStream container = new();
        await FormatTestData.WriteHeaderAsync(container, shape, cipher);
        byte[] onTheWire = container.ToArray();
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, FormatTestData.MethodOf(shape), DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(onTheWire, parsed.HeaderBytes);
    }

    [Theory]
    [MemberData(nameof(ShapesAndCiphers))]
    public async Task TheHeaderLengthIsTheOffsetOfTheFirstPayloadByte(HeaderShape shape, Cipher cipher)
    {
        byte[] payload = FormatTestData.Sequence(0xC0, 64);

        using MemoryStream container = new();
        await FormatTestData.WriteHeaderAsync(container, shape, cipher);
        await container.WriteAsync(payload, 0, payload.Length, TestContext.Current.CancellationToken);
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, FormatTestData.MethodOf(shape), DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(FormatTestData.HeaderLengthOf(shape), parsed.Header.HeaderLength);
        Assert.Equal(parsed.Header.HeaderLength, parsed.HeaderBytes.Length);

        // The reader consumed the header and no more, so the payload is intact and readable from here.
        Assert.Equal(parsed.Header.HeaderLength, container.Position);

        byte[] remaining = new byte[payload.Length];
        int read = await container.ReadAsync(remaining, 0, remaining.Length, TestContext.Current.CancellationToken);
        Assert.Equal(payload.Length, read);
        Assert.Equal(payload, remaining);
    }

    [Theory]
    [MemberData(nameof(ShapesAndCiphers))]
    public async Task TheCommonPrefixRoundTrips(HeaderShape shape, Cipher cipher)
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            await FormatTestData.BuildHeaderAsync(shape, cipher));

        Assert.Equal(FormatTestData.MethodOf(shape), parsed.Header.Method);
        Assert.Equal(DataEncryptionDefaults.FormatVersion, parsed.Header.FormatVersion);
        Assert.Equal(cipher, parsed.Header.Cipher);
        Assert.Equal(FormatTestData.Nonce(), parsed.Nonce);
        Assert.Equal(DataEncryptionDefaults.KeyConfirmationTagSizeBytes, parsed.KeyConfirmationTag.Length);
    }

    // --- Method-specific fields --------------------------------------------------------------------

    [Fact]
    public async Task Pbkdf2FieldsRoundTrip()
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2));

        Assert.Equal(FormatTestData.Salt(), parsed.Salt);
        Assert.Equal(DataEncryptionDefaults.Pbkdf2Iterations, parsed.Header.Pbkdf2Iterations);
        Assert.Equal(53, parsed.Header.HeaderLength);

        // Fields that belong to other methods stay null.
        Assert.Null(parsed.Header.Argon2Iterations);
        Assert.Null(parsed.Header.Argon2MemorySizeKb);
        Assert.Null(parsed.Header.Argon2DegreeOfParallelism);
        Assert.Null(parsed.Header.WrappedKeyLength);
        Assert.Null(parsed.Header.EncapsulationLength);
        Assert.Null(parsed.Header.MLKemParameterSet);
        Assert.Null(parsed.WrappedKey);
        Assert.Null(parsed.Encapsulation);
    }

    [Fact]
    public async Task Argon2FieldsRoundTrip()
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2));

        Assert.Equal(FormatTestData.Salt(), parsed.Salt);
        Assert.Equal(DataEncryptionDefaults.Argon2Iterations, parsed.Header.Argon2Iterations);
        Assert.Equal(DataEncryptionDefaults.Argon2DegreeOfParallelism, parsed.Header.Argon2DegreeOfParallelism);
        Assert.Equal(DataEncryptionDefaults.Argon2MemorySizeKb, parsed.Header.Argon2MemorySizeKb);
        Assert.Equal(61, parsed.Header.HeaderLength);

        Assert.Null(parsed.Header.Pbkdf2Iterations);
        Assert.Null(parsed.Header.WrappedKeyLength);
        Assert.Null(parsed.Header.EncapsulationLength);
        Assert.Null(parsed.Header.MLKemParameterSet);
    }

    /// <summary>
    /// The three Argon2 cost fields are distinguished only by their offsets, so a test whose values all
    /// coincide would not notice them being swapped. These three are pairwise different.
    /// </summary>
    [Fact]
    public async Task TheThreeArgon2CostFieldsAreNotInterchanged()
    {
        using MemoryStream container = new();
        await HeaderWriter.WriteArgon2HeaderAsync(
            container,
            Cipher.Aes256Gcm,
            FormatTestData.Nonce(),
            FormatTestData.Salt(),
            iterations: 7,
            degreeOfParallelism: 11,
            memorySizeKb: 4096,
            FormatTestData.DataKey(),
            FormatTestData.HmacSha256(),
            CancellationToken.None);
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, EncryptionMethod.Argon2, DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(7, parsed.Header.Argon2Iterations);
        Assert.Equal(11, parsed.Header.Argon2DegreeOfParallelism);
        Assert.Equal(4096, parsed.Header.Argon2MemorySizeKb);
    }

    [Fact]
    public async Task RsaFieldsRoundTrip()
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa));

        Assert.Equal(FormatTestData.WrappedKey(), parsed.WrappedKey);
        Assert.Equal(FormatTestData.RsaWrappedKeyLength, parsed.Header.WrappedKeyLength);
        Assert.Equal(37 + FormatTestData.RsaWrappedKeyLength, parsed.Header.HeaderLength);

        Assert.Null(parsed.Salt);
        Assert.Null(parsed.Header.Pbkdf2Iterations);
        Assert.Null(parsed.Header.EncapsulationLength);
        Assert.Null(parsed.Header.MLKemParameterSet);
    }

    [Fact]
    public async Task MLKemFieldsRoundTrip()
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem));

        Assert.Equal(FormatTestData.Encapsulation(), parsed.Encapsulation);
        Assert.Equal(FormatTestData.MLKemEncapsulationLength, parsed.Header.EncapsulationLength);
        Assert.Equal(FormatTestData.MLKemFixtureParameterSet, parsed.Header.MLKemParameterSet);
        Assert.Equal(FormatTestData.MLKemFixtureParameterSet, parsed.MLKemParameterSet);
        Assert.Equal(38 + FormatTestData.MLKemEncapsulationLength, parsed.Header.HeaderLength);

        Assert.Null(parsed.Salt);
        Assert.Null(parsed.Header.WrappedKeyLength);
    }

    /// <summary>
    /// The hybrid shape is the only one that populates <b>both</b> variable-length fields and the
    /// parameter-set byte at once, so the assertion worth making is that all three arrive together and
    /// that nothing else does.
    /// </summary>
    [Fact]
    public async Task HybridFieldsRoundTrip()
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            await FormatTestData.BuildHeaderAsync(HeaderShape.Hybrid));

        Assert.Equal(FormatTestData.WrappedKey(), parsed.WrappedKey);
        Assert.Equal(FormatTestData.Encapsulation(), parsed.Encapsulation);
        Assert.Equal(FormatTestData.RsaWrappedKeyLength, parsed.Header.WrappedKeyLength);
        Assert.Equal(FormatTestData.MLKemEncapsulationLength, parsed.Header.EncapsulationLength);
        Assert.Equal(FormatTestData.MLKemFixtureParameterSet, parsed.Header.MLKemParameterSet);
        Assert.Equal(FormatTestData.MLKemFixtureParameterSet, parsed.MLKemParameterSet);
        Assert.Equal(
            42 + FormatTestData.RsaWrappedKeyLength + FormatTestData.MLKemEncapsulationLength,
            parsed.Header.HeaderLength);

        Assert.Null(parsed.Salt);
        Assert.Null(parsed.Header.Pbkdf2Iterations);
        Assert.Null(parsed.Header.Argon2Iterations);
        Assert.Null(parsed.Header.Argon2MemorySizeKb);
        Assert.Null(parsed.Header.Argon2DegreeOfParallelism);
    }

    /// <summary>
    /// The hybrid's two variable-length fields must not be interchanged. Every combination of a real RSA
    /// modulus size and a real ML-KEM encapsulation length is round-tripped, and the two are never equal —
    /// so a reader that read them in the wrong order, or that used one length for both, cannot pass.
    /// </summary>
    public static TheoryData<int, int> HybridFieldLengths()
    {
        TheoryData<int, int> data = [];
        foreach (int wrappedSecretLength in new[] { 256, 384, 512 })
        {
            foreach (int encapsulationLength in new[] { 768, 1_088, 1_568 })
            {
                data.Add(wrappedSecretLength, encapsulationLength);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(HybridFieldLengths))]
    public async Task TheHybridsTwoVariableLengthFieldsAreNotInterchanged(
        int wrappedSecretLength,
        int encapsulationLength)
    {
        // Distinct fill bytes as well as distinct lengths, so a swap is visible in the content too.
        byte[] wrappedSecret = FormatTestData.Sequence(0x11, wrappedSecretLength);
        byte[] encapsulation = FormatTestData.Sequence(0x99, encapsulationLength);

        using MemoryStream container = new();
        await HeaderWriter.WriteHybridHeaderAsync(
            container,
            Cipher.Camellia256Gcm,
            MLKemParameterSet.MLKem768,
            FormatTestData.Nonce(),
            wrappedSecret,
            encapsulation,
            FormatTestData.DataKey(),
            FormatTestData.HmacSha256(),
            CancellationToken.None);
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, EncryptionMethod.Hybrid, DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(wrappedSecret, parsed.WrappedKey);
        Assert.Equal(encapsulation, parsed.Encapsulation);
        Assert.Equal(wrappedSecretLength, parsed.Header.WrappedKeyLength);
        Assert.Equal(encapsulationLength, parsed.Header.EncapsulationLength);
        Assert.Equal(42 + wrappedSecretLength + encapsulationLength, parsed.Header.HeaderLength);
    }

    /// <summary>All three ML-KEM parameter sets round-trip through the hybrid's header byte too.</summary>
    [Theory]
    [InlineData(MLKemParameterSet.MLKem512)]
    [InlineData(MLKemParameterSet.MLKem768)]
    [InlineData(MLKemParameterSet.MLKem1024)]
    public async Task EveryMLKemParameterSetRoundTripsInAHybridHeader(MLKemParameterSet parameterSet)
    {
        using MemoryStream container = new();
        await HeaderWriter.WriteHybridHeaderAsync(
            container,
            Cipher.Serpent256Gcm,
            parameterSet,
            FormatTestData.Nonce(),
            FormatTestData.WrappedKey(),
            FormatTestData.Encapsulation(),
            FormatTestData.DataKey(),
            FormatTestData.HmacSha256(),
            CancellationToken.None);
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, EncryptionMethod.Hybrid, DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(parameterSet, parsed.Header.MLKemParameterSet);
    }

    /// <summary>All three ML-KEM parameter sets round-trip through the header byte.</summary>
    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, 768)]
    [InlineData(MLKemParameterSet.MLKem768, 1088)]
    [InlineData(MLKemParameterSet.MLKem1024, 1568)]
    public async Task EveryMLKemParameterSetRoundTrips(MLKemParameterSet parameterSet, int encapsulationLength)
    {
        byte[] encapsulation = FormatTestData.Sequence(0x55, encapsulationLength);

        using MemoryStream container = new();
        await HeaderWriter.WriteMLKemHeaderAsync(
            container,
            Cipher.Camellia256Gcm,
            parameterSet,
            FormatTestData.Nonce(),
            encapsulation,
            FormatTestData.DataKey(),
            FormatTestData.HmacSha256(),
            CancellationToken.None);
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, EncryptionMethod.MLKem, DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(parameterSet, parsed.Header.MLKemParameterSet);
        Assert.Equal(encapsulation, parsed.Encapsulation);
        Assert.Equal(38 + encapsulationLength, parsed.Header.HeaderLength);
    }

    /// <summary>RSA moduli from 2048 to 4096 bits, to exercise the variable-length field.</summary>
    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(512)]
    public async Task EveryRsaModulusSizeRoundTrips(int wrappedKeyLength)
    {
        byte[] wrappedKey = FormatTestData.Sequence(0x33, wrappedKeyLength);

        using MemoryStream container = new();
        await HeaderWriter.WriteRsaHeaderAsync(
            container,
            Cipher.Serpent256Gcm,
            FormatTestData.Nonce(),
            wrappedKey,
            FormatTestData.DataKey(),
            FormatTestData.HmacSha256(),
            CancellationToken.None);
        container.Position = 0;

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            container, EncryptionMethod.Rsa, DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(wrappedKey, parsed.WrappedKey);
        Assert.Equal(37 + wrappedKeyLength, parsed.Header.HeaderLength);
    }

    // --- The tag the writer sealed is the tag the reader confirms -----------------------------------

    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task TheWrittenTagConfirmsUnderTheSameDataKey(HeaderShape shape)
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(await FormatTestData.BuildHeaderAsync(shape));

        Assert.True(KeyConfirmation.Verify(
            FormatTestData.HmacSha256(),
            FormatTestData.DataKey(),
            parsed.BytesBeforeTag,
            parsed.KeyConfirmationTag));
    }

    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task TheWrittenTagDoesNotConfirmUnderADifferentDataKey(HeaderShape shape)
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(await FormatTestData.BuildHeaderAsync(shape));

        Assert.False(KeyConfirmation.Verify(
            FormatTestData.HmacSha256(),
            FormatTestData.WithFlippedBit(FormatTestData.DataKey(), 0),
            parsed.BytesBeforeTag,
            parsed.KeyConfirmationTag));
    }

    /// <summary>
    /// <see cref="ParsedHeader.BytesBeforeTag"/> must be the header minus exactly the trailing tag —
    /// the message §6 says the tag is computed over.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task BytesBeforeTagIsTheHeaderMinusTheTag(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(header);

        int tagOffset = header.Length - DataEncryptionDefaults.KeyConfirmationTagSizeBytes;
        Assert.Equal(header[..tagOffset], parsed.BytesBeforeTag);
        Assert.Equal(header[tagOffset..], parsed.KeyConfirmationTag);
    }

    // --- Non-seekable input ------------------------------------------------------------------------

    /// <summary>
    /// Decryption must not require a seekable stream (<c>docs/format.md</c> §7.2), so the reader is
    /// exercised over a stream that reports itself unseekable and hands back one byte at a time —
    /// which also proves the tee mirrors short reads correctly.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task TheReaderWorksOverANonSeekableDripFedStream(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);

        using DripFeedStream input = new(header);
        ParsedHeader parsed = await HeaderReader.ReadAsync(
            input, FormatTestData.MethodOf(shape), DataEncryptionLimits.Default, CancellationToken.None);

        Assert.Equal(header, parsed.HeaderBytes);
    }

    /// <summary>
    /// A forward-only stream that reports <see cref="CanSeek"/> as <see langword="false"/> and never
    /// returns more than one byte per read.
    /// </summary>
    private sealed class DripFeedStream(byte[] content) : Stream
    {
        private int _position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count == 0 || _position >= content.Length) return 0;

            buffer[offset] = content[_position++];
            return 1;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
