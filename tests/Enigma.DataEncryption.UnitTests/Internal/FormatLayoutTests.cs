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
    public void TheFourHeaderLengthsMatchTheSpecification()
    {
        Assert.Equal(53, FormatLayout.Pbkdf2HeaderLength);
        Assert.Equal(61, FormatLayout.Argon2HeaderLength);
        Assert.Equal(37, FormatLayout.RsaHeaderBaseLength);
        Assert.Equal(38, FormatLayout.MLKemHeaderBaseLength);
    }

    /// <summary>A written header must be exactly as long as the layout says.</summary>
    [Theory]
    [InlineData(HeaderShape.Pbkdf2, 53)]
    [InlineData(HeaderShape.Argon2, 61)]
    public async Task AFixedLengthHeaderIsExactlyTheSpecifiedLength(HeaderShape shape, int expected) =>
        Assert.Equal(expected, (await FormatTestData.BuildHeaderAsync(shape)).Length);

    [Fact]
    public async Task AnRsaHeaderIs37PlusTheWrappedKeyLength() =>
        Assert.Equal(
            37 + FormatTestData.RsaWrappedKeyLength,
            (await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa)).Length);

    [Fact]
    public async Task AnMLKemHeaderIs38PlusTheEncapsulationLength() =>
        Assert.Equal(
            38 + FormatTestData.MLKemEncapsulationLength,
            (await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem)).Length);

    /// <summary>
    /// The ML-KEM header is one byte longer than the RSA header for the same variable-length payload —
    /// the parameter-set byte — which is the only structural difference between the two shapes' fixed
    /// parts.
    /// </summary>
    [Fact]
    public void TheMLKemBaseIsOneByteLongerThanTheRsaBase() =>
        Assert.Equal(FormatLayout.RsaHeaderBaseLength + 1, FormatLayout.MLKemHeaderBaseLength);
}
