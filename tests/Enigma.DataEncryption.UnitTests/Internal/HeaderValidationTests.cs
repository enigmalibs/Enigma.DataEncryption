using System.Threading.Tasks;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Covers every rejection <see cref="HeaderReader"/> owes the error mapping of <c>docs/format.md</c> §9:
/// the magic, the method byte (including the reserved <c>0x05</c>), the version byte (including the whole
/// reserved legacy range), the cipher byte, the ML-KEM parameter-set byte, and every cost and length
/// field.
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
    /// <c>0x05</c> is reserved for the hybrid method and must be rejected by a reader of this format
    /// version, with a message that says so rather than "undefined".
    /// </summary>
    [Fact]
    public async Task TheReservedHybridMethodByteIsRejectedAsReserved()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(FormatTestData.WithByteAt(header, 2, 0x05)));

        Assert.Contains("reserved", exception.Message);
    }

    /// <summary>
    /// Each service reads only its own method byte, so handing it another method's container is a format
    /// error rather than a misparse — all twelve mismatched pairs.
    /// </summary>
    public static TheoryData<HeaderShape, EncryptionMethod> MismatchedMethods()
    {
        TheoryData<HeaderShape, EncryptionMethod> data = [];
        foreach (HeaderShape shape in new[] { HeaderShape.Pbkdf2, HeaderShape.Argon2, HeaderShape.Rsa, HeaderShape.MLKem })
        {
            foreach (EncryptionMethod method in new[]
                     {
                         EncryptionMethod.Pbkdf2, EncryptionMethod.Argon2,
                         EncryptionMethod.Rsa, EncryptionMethod.MLKem,
                     })
            {
                if (FormatTestData.MethodOf(shape) != method) data.Add(shape, method);
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

    /// <summary>And the inspector, which expects no particular method, reads all four.</summary>
    [Theory]
    [InlineData(HeaderShape.Pbkdf2)]
    [InlineData(HeaderShape.Argon2)]
    [InlineData(HeaderShape.Rsa)]
    [InlineData(HeaderShape.MLKem)]
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
                FormatTestData.WithInt32At(header, 17, length), EncryptionMethod.Rsa));
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

    /// <summary>
    /// An enormous announced length must be rejected by arithmetic, before anything is allocated for it.
    /// A reader that allocated first would fail with <c>OutOfMemoryException</c> instead — the very
    /// denial-of-service the caps exist to prevent.
    /// </summary>
    [Fact]
    public async Task AnEnormousWrappedKeyLengthIsRejectedWithoutAllocating()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);
        byte[] patched = FormatTestData.WithInt32At(header, 17, int.MaxValue);

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
