using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Covers every rejection <see cref="HeaderReader"/> owes the error mapping of <c>docs/format.md</c> §9:
/// the magic, the method byte, the version byte (including the whole reserved legacy range), the cipher
/// byte, the ML-KEM parameter-set byte, and every cost and length field.
/// </summary>
public sealed class HeaderValidationTests
{
    // --- §2.1 Magic --------------------------------------------------------------------------------

    [Theory]
    [InlineData(0x00)]
    [InlineData(0xDE)]
    [InlineData(0xEB)]
    [InlineData(0xFF)]
    public async Task AWrongFirstMagicByteIsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 0, value)));
    }

    /// <summary>
    /// The second byte is checked independently of the first — a reader that only looks at one of them
    /// accepts half the wrong files there are.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0xEC)]
    [InlineData(0xDF)]
    [InlineData(0xFF)]
    public async Task AWrongSecondMagicByteIsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 1, value)));
    }

    /// <summary>The magic is <c>EC DE</c> in that order, so the swapped pair must be rejected.</summary>
    [Fact]
    public async Task ASwappedMagicIsAFormatError()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);
        byte[] patched = FormatTestData.WithByteAt(FormatTestData.WithByteAt(header, 0, 0xDE), 1, 0xEC);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(() => FormatTestData.ReadHeaderAsync(patched));
    }

    // --- §2.2 Method -------------------------------------------------------------------------------

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x06)]
    [InlineData(0x07)]
    [InlineData(0x10)]
    [InlineData(0xFF)]
    public async Task AnUndefinedMethodByteIsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 2, value)));
    }

    /// <summary>
    /// <c>0x05</c> is <b>no longer</b> reserved: it is the hybrid method, so a reader must accept it as a
    /// method byte and then fail on the body that does not follow. Earlier revisions of the format
    /// rejected the byte outright with a message naming the reservation, so this is what would catch the
    /// assignment being made in the enum but not in the reader.
    /// </summary>
    /// <remarks>
    /// The failure it does produce is the parameter-set byte: relabelling a PBKDF2 header makes the reader
    /// look for a parameter set at offset 5, where the nonce's first byte — <c>0x00</c> — sits. That
    /// <c>0x00</c> is never a valid parameter set is exactly why the wire encoding is 1-based (§3.4).
    /// </remarks>
    [Fact]
    public async Task TheHybridMethodByteIsNoLongerRejectedAsReserved()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 2, 0x05)));

        Assert.DoesNotContain("reserved", exception.Message);
        Assert.Contains("parameter-set byte", exception.Message);
    }

    /// <summary>
    /// And the one method byte that is genuinely absent from the enum now sits at <c>0x06</c>, where the
    /// message must say "undefined" rather than name a method.
    /// </summary>
    [Fact]
    public async Task TheFirstUnassignedMethodByteIsRejectedAsUndefined()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 2, 0x06)));

        Assert.Contains("Undefined container method byte 0x06", exception.Message);
    }

    /// <summary>
    /// Each service reads only its own method byte, so handing it another method's container is a format
    /// error rather than a misparse — all twenty mismatched pairs.
    /// </summary>
    public static TheoryData<HeaderShape, EncryptionMethod> MismatchedMethods()
    {
        TheoryData<HeaderShape, EncryptionMethod> data = [];
        foreach (HeaderShape shape in FormatTestData.AllShapes)
        {
            foreach (HeaderShape other in FormatTestData.AllShapes)
            {
                if (shape != other) data.Add(shape, FormatTestData.MethodOf(other));
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(MismatchedMethods))]
    public async Task AContainerFromAnotherMethodIsAFormatError(HeaderShape shape, EncryptionMethod expected)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(header, expected));
    }

    /// <summary>Every header shape.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<HeaderShape> Shapes() => [.. FormatTestData.AllShapes];

    /// <summary>And the inspector, which expects no particular method, reads all five.</summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task NoExpectedMethodAcceptsEveryMethod(HeaderShape shape)
    {
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(await FormatTestData.BuildHeaderAsync(shape));

        Assert.Equal(FormatTestData.MethodOf(shape), parsed.Header.Method);
    }

    // --- §2.3 Format version -----------------------------------------------------------------------

    /// <summary>
    /// Every reserved legacy value <c>0x01</c>–<c>0x0F</c>, plus <c>0x00</c> and a selection above
    /// <c>0x10</c>. A legacy container must be refused cleanly, not parsed as if it were this format.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x01)]
    [InlineData(0x02)]
    [InlineData(0x03)]
    [InlineData(0x04)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0x07)]
    [InlineData(0x08)]
    [InlineData(0x09)]
    [InlineData(0x0A)]
    [InlineData(0x0B)]
    [InlineData(0x0C)]
    [InlineData(0x0D)]
    [InlineData(0x0E)]
    [InlineData(0x0F)]
    [InlineData(0x11)]
    [InlineData(0x20)]
    [InlineData(0xFF)]
    public async Task AVersionByteOtherThan0x10IsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 3, value)));
    }

    // --- §2.4 Cipher -------------------------------------------------------------------------------

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0xFF)]
    public async Task AnUndefinedCipherByteIsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 4, value)));
    }

    // --- §3.4 ML-KEM parameter set -----------------------------------------------------------------

    /// <summary>
    /// <c>0x00</c> matters most here: the wire encoding is 1-based precisely so a zero-filled header
    /// cannot parse.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x04)]
    [InlineData(0x05)]
    [InlineData(0xFF)]
    public async Task AnUndefinedMLKemParameterSetByteIsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithByteAt(header, 5, value), EncryptionMethod.MLKem));
    }

    // --- §3.3 RSA OAEP hash ------------------------------------------------------------------------

    /// <summary>
    /// Method <c>0x03</c>'s selector shares offset 5 with ML-KEM's and is rejected on the same terms:
    /// <c>0x00</c> because the encoding is 1-based, and everything from <c>0x05</c> up because it is
    /// undefined.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0x7F)]
    [InlineData(0xFF)]
    public async Task AnUndefinedOaepHashByteIsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithByteAt(header, 5, value), EncryptionMethod.Rsa));
    }

    /// <summary>
    /// <c>0x01</c> is the one value that is <b>reserved</b> rather than undefined (<c>docs/format.md</c>
    /// §10), and the message says so — the distinction is what makes a later un-reservation a one-line
    /// change rather than a re-examination of what readers were told.
    /// </summary>
    [Fact]
    public async Task TheReservedSha1HashByteIsRejectedAsReserved()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithByteAt(header, 5, 0x01), EncryptionMethod.Rsa));

        Assert.Contains("reserved", exception.Message);
        Assert.Contains("SHA-1", exception.Message);
    }

    /// <summary>
    /// The three accepted values parse and are reported as read — the counterpart to the rejections above,
    /// so the theory is not merely asserting that the reader rejects everything.
    /// </summary>
    [Theory]
    [InlineData(0x02, RsaOaepHash.Sha256)]
    [InlineData(0x03, RsaOaepHash.Sha384)]
    [InlineData(0x04, RsaOaepHash.Sha512)]
    public async Task AnAcceptedOaepHashByteParsesAndIsReported(byte value, RsaOaepHash expected)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);

        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            FormatTestData.WithByteAt(header, 5, value), EncryptionMethod.Rsa);

        Assert.Equal(expected, parsed.RsaOaepHash);
        Assert.Equal(expected, parsed.Header.RsaOaepHash);
    }

    // --- §8 Cost and length fields -----------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    [InlineData(10_000_001)]
    public async Task AnOutOfRangePbkdf2IterationCountIsAFormatError(int iterations)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 33, iterations), EncryptionMethod.Pbkdf2));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    [InlineData(65)]
    public async Task AnOutOfRangeArgon2IterationCountIsAFormatError(int iterations)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 33, iterations), EncryptionMethod.Argon2));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    [InlineData(65)]
    public async Task AnOutOfRangeArgon2ParallelismIsAFormatError(int degreeOfParallelism)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 37, degreeOfParallelism), EncryptionMethod.Argon2));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    [InlineData(1_048_577)]
    public async Task AnOutOfRangeArgon2MemorySizeIsAFormatError(int memorySizeKb)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 41, memorySizeKb), EncryptionMethod.Argon2));
    }

    /// <summary>
    /// The costs in the header are what the reader reports, and they are accepted right up to the cap.
    /// </summary>
    [Fact]
    public async Task CostFieldsAtTheCapAreAccepted()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2);
        byte[] patched = FormatTestData.WithInt32At(header, 33, 64);
        patched = FormatTestData.WithInt32At(patched, 37, 64);
        patched = FormatTestData.WithInt32At(patched, 41, 1_048_576);

        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(patched, EncryptionMethod.Argon2);

        Assert.Equal(64, parsed.Header.Argon2Iterations);
        Assert.Equal(64, parsed.Header.Argon2DegreeOfParallelism);
        Assert.Equal(1_048_576, parsed.Header.Argon2MemorySizeKb);
    }

    /// <summary>A tightened <see cref="DataEncryptionLimits"/> must be the bound actually applied.</summary>
    [Fact]
    public async Task TightenedLimitsAreApplied()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);
        DataEncryptionLimits tightened = new() { MaxPbkdf2Iterations = 1_000 };

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(header, EncryptionMethod.Pbkdf2, tightened));

        // The very same container parses under the default bounds.
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(header, EncryptionMethod.Pbkdf2);
        Assert.Equal(DataEncryptionDefaults.Pbkdf2Iterations, parsed.Header.Pbkdf2Iterations);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    [InlineData(4_097)]
    public async Task AnOutOfRangeWrappedKeyLengthIsAFormatError(int length)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 18, length), EncryptionMethod.Rsa));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    [InlineData(4_097)]
    public async Task AnOutOfRangeEncapsulationLengthIsAFormatError(int length)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 18, length), EncryptionMethod.MLKem));
    }

    // --- §3.5 The hybrid's two length fields and its parameter-set byte -----------------------------

    /// <summary>
    /// The hybrid's parameter-set byte sits at the same offset 5 as ML-KEM's and is rejected on the same
    /// terms — <c>0x00</c> included, which is what stops a zero-filled header from parsing.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x04)]
    [InlineData(0x05)]
    [InlineData(0xFF)]
    public async Task AnUndefinedParameterSetByteInAHybridHeaderIsAFormatError(byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Hybrid);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithByteAt(header, 5, value), EncryptionMethod.Hybrid));
    }

    /// <summary>
    /// The hybrid's <b>first</b> length field, at offset 18, bounded by the RSA cap — the hybrid adds no
    /// cap of its own (<c>docs/format.md</c> §8).
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    [InlineData(4_097)]
    public async Task AnOutOfRangeHybridWrappedSecretLengthIsAFormatError(int length)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Hybrid);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 18, length), EncryptionMethod.Hybrid));
    }

    /// <summary>
    /// The hybrid's <b>second</b> length field, whose offset is itself a function of the first field's
    /// value: 22 + <c>N</c> = 278 for the 256-byte fixture.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    [InlineData(4_097)]
    public async Task AnOutOfRangeHybridEncapsulationLengthIsAFormatError(int length)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Hybrid);
        int offset = FormatLayout.HybridEncapsulationLengthOffset(FormatTestData.RsaWrappedKeyLength);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, offset, length), EncryptionMethod.Hybrid));
    }

    /// <summary>
    /// A reader that hard-coded ML-KEM's offset 18 for the hybrid's second length field would corrupt the
    /// <i>first</i> length instead and fail naming the wrong field, so the two are told apart by the field
    /// name in the message.
    /// </summary>
    /// <remarks>
    /// Zero is the value that reaches <see cref="LimitsValidator"/> — and therefore the field's name — at
    /// all: Enigma.Core's <c>ReadLengthValueAsync</c> applies its own cap first and rejects anything
    /// negative or over it with a message that names no field, which is why the theory above asserts only
    /// the exception type.
    /// </remarks>
    [Fact]
    public async Task TheHybridsTwoLengthFieldsAreRejectedByName()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Hybrid);
        int encapsulationLengthOffset =
            FormatLayout.HybridEncapsulationLengthOffset(FormatTestData.RsaWrappedKeyLength);

        DataEncryptionFormatException wrapped = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, 18, 0), EncryptionMethod.Hybrid));
        Assert.Contains("RSA wrapped-key length", wrapped.Message);

        DataEncryptionFormatException encapsulation = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                FormatTestData.WithInt32At(header, encapsulationLengthOffset, 0), EncryptionMethod.Hybrid));
        Assert.Contains("ML-KEM encapsulation length", encapsulation.Message);
    }

    /// <summary>
    /// Both of the hybrid's length fields are accepted right at their caps, and the two caps are the RSA
    /// and ML-KEM ones rather than anything hybrid-specific.
    /// </summary>
    [Fact]
    public async Task TheHybridsLengthFieldsAreBoundedByTheRsaAndMLKemCaps()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Hybrid);
        int encapsulationLengthOffset =
            FormatLayout.HybridEncapsulationLengthOffset(FormatTestData.RsaWrappedKeyLength);

        // Tightening the RSA cap alone refuses the container...
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                header,
                EncryptionMethod.Hybrid,
                new DataEncryptionLimits { MaxWrappedKeyLength = FormatTestData.RsaWrappedKeyLength - 1 }));

        // ...and so does tightening the ML-KEM cap alone.
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(
                header,
                EncryptionMethod.Hybrid,
                new DataEncryptionLimits
                {
                    MaxEncapsulationLength = FormatTestData.MLKemEncapsulationLength - 1,
                }));

        // Exactly at both caps is legal — the caps include their own value.
        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(
            header,
            EncryptionMethod.Hybrid,
            new DataEncryptionLimits
            {
                MaxWrappedKeyLength = FormatTestData.RsaWrappedKeyLength,
                MaxEncapsulationLength = FormatTestData.MLKemEncapsulationLength,
            });

        Assert.Equal(FormatTestData.RsaWrappedKeyLength, parsed.Header.WrappedKeyLength);
        Assert.Equal(FormatTestData.MLKemEncapsulationLength, parsed.Header.EncapsulationLength);
        Assert.Equal(278, encapsulationLengthOffset);
    }

    /// <summary>
    /// An enormous announced length must be rejected by arithmetic, before anything is allocated for it.
    /// A reader that allocated first would fail with <c>OutOfMemoryException</c> instead — the very
    /// denial-of-service the caps exist to prevent.
    /// </summary>
    [Fact]
    public async Task AnEnormousWrappedKeyLengthIsRejectedWithoutAllocating()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);
        byte[] patched = FormatTestData.WithInt32At(header, 18, int.MaxValue);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(patched, EncryptionMethod.Rsa));
    }

    /// <summary>
    /// The parsed header must reflect the bytes on the wire, not the writer's intent: a header whose
    /// cipher byte has been edited to another valid cipher parses, and reports the edited value. Catching
    /// that edit is the AAD's job, not the parser's — see <c>docs/format.md</c> §5.
    /// </summary>
    [Fact]
    public async Task AnEditedButValidCipherByteParsesAndIsReported()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2, Cipher.Aes256Gcm);
        byte[] patched = FormatTestData.WithByteAt(header, 4, (byte)Cipher.Camellia256Gcm);

        ParsedHeader parsed = await FormatTestData.ReadHeaderAsync(patched, EncryptionMethod.Pbkdf2);

        Assert.Equal(Cipher.Camellia256Gcm, parsed.Header.Cipher);

        // …and the confirmation tag no longer matches, because it covers that byte.
        Assert.False(KeyConfirmation.Verify(
            FormatTestData.HmacSha256(),
            FormatTestData.DataKey(),
            parsed.BytesBeforeTag,
            parsed.KeyConfirmationTag));
    }
}
