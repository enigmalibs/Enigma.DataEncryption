using System.Threading.Tasks;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Pins <see cref="FormatLayout"/>'s offset arithmetic against the literal numbers in
/// <c>docs/format.md</c> §3, and against the length of the headers actually produced.
/// </summary>
/// <remarks>
/// <see cref="FormatLayout"/> computes its lengths from <see cref="DataEncryptionDefaults"/>, which keeps
/// the code self-consistent but would happily agree with itself about a wrong number. The literals here
/// are transcribed from the specification, so the two must meet.
/// </remarks>
public sealed class FormatLayoutTests
{
    [Fact]
    public void TheMagicIsEcDe()
    {
        Assert.Equal(0xEC, FormatLayout.MagicByte0);
        Assert.Equal(0xDE, FormatLayout.MagicByte1);
        Assert.Equal(2, FormatLayout.MagicLength);
    }

    [Fact]
    public void TheCommonPrefixIsFiveBytes() => Assert.Equal(5, FormatLayout.CommonPrefixLength);

    [Fact]
    public void TheFiveHeaderLengthsMatchTheSpecification()
    {
        Assert.Equal(53, FormatLayout.Pbkdf2HeaderLength);
        Assert.Equal(61, FormatLayout.Argon2HeaderLength);
        Assert.Equal(38, FormatLayout.RsaHeaderBaseLength);
        Assert.Equal(38, FormatLayout.MLKemHeaderBaseLength);
        Assert.Equal(42, FormatLayout.HybridHeaderBaseLength);
    }

    /// <summary>
    /// The two one-byte algorithm selectors at offset 5 are separate constants on purpose, so each
    /// header shape's arithmetic reads on its own — but both are one byte.
    /// </summary>
    [Fact]
    public void BothOffsetFiveSelectorsAreOneByte()
    {
        Assert.Equal(1, FormatLayout.OaepHashLength);
        Assert.Equal(1, FormatLayout.ParameterSetLength);
    }

    /// <summary>A written header must be exactly as long as the layout says.</summary>
    [Theory]
    [InlineData(HeaderShape.Pbkdf2, 53)]
    [InlineData(HeaderShape.Argon2, 61)]
    public async Task AFixedLengthHeaderIsExactlyTheSpecifiedLength(HeaderShape shape, int expected) =>
        Assert.Equal(expected, (await FormatTestData.BuildHeaderAsync(shape)).Length);

    [Fact]
    public async Task AnRsaHeaderIs38PlusTheWrappedKeyLength() =>
        Assert.Equal(
            38 + FormatTestData.RsaWrappedKeyLength,
            (await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa)).Length);

    [Fact]
    public async Task AnMLKemHeaderIs38PlusTheEncapsulationLength() =>
        Assert.Equal(
            38 + FormatTestData.MLKemEncapsulationLength,
            (await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem)).Length);

    [Fact]
    public async Task AHybridHeaderIs42PlusBothVariableLengths() =>
        Assert.Equal(
            42 + FormatTestData.RsaWrappedKeyLength + FormatTestData.MLKemEncapsulationLength,
            (await FormatTestData.BuildHeaderAsync(HeaderShape.Hybrid)).Length);

    /// <summary>
    /// The two public-key shapes' fixed parts are now the <b>same</b> length: each carries a one-byte
    /// algorithm selector at offset 5 — the OAEP hash for RSA, the parameter set for ML-KEM — so their
    /// fixed parts differ only in what the bytes at offsets 2 and 5 mean, not in how many there are.
    /// </summary>
    /// <remarks>
    /// This assertion used to read <c>RsaHeaderBaseLength + 1 == MLKemHeaderBaseLength</c>, when the RSA
    /// shape had no selector. <c>FEATURE-0D64</c> gave it one at the same offset, which is what made the
    /// two equal — see <c>docs/format.md</c> §3.3.
    /// </remarks>
    [Fact]
    public void TheTwoPublicKeyBasesAreTheSameLength() =>
        Assert.Equal(FormatLayout.RsaHeaderBaseLength, FormatLayout.MLKemHeaderBaseLength);

    /// <summary>
    /// The hybrid base is four bytes longer than the ML-KEM base, and the four bytes are the second
    /// length field: the hybrid is the only shape carrying two variable-length fields, and therefore two
    /// lengths.
    /// </summary>
    [Fact]
    public void TheHybridBaseIsOneInt32LongerThanTheMLKemBase() =>
        Assert.Equal(
            FormatLayout.MLKemHeaderBaseLength + FormatLayout.Int32Length,
            FormatLayout.HybridHeaderBaseLength);

    /// <summary>
    /// The combiner transcript is defined as a header slice (<c>docs/format.md</c> §3.5.1), so the offset
    /// it starts at — the first length field, at 18 — must be where the layout puts it, and the second
    /// length field must follow the first value.
    /// </summary>
    [Fact]
    public void TheHybridLengthFieldOffsetsAreWhereTheSpecificationPutsThem()
    {
        Assert.Equal(18, FormatLayout.HybridWrappedSecretLengthOffset);
        Assert.Equal(278, FormatLayout.HybridEncapsulationLengthOffset(256));
        Assert.Equal(534, FormatLayout.HybridEncapsulationLengthOffset(512));
    }
}
