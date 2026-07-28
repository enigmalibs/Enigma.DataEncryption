using System;
using System.Linq;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Pins the RSA-OAEP hash wire encoding of <c>docs/format.md</c> §3.3 — the second place in this library
/// where an enum's numeric value and its wire byte deliberately differ, and the only one whose numbering
/// includes a value the format rejects.
/// </summary>
public sealed class RsaOaepHashWireTests
{
    [Theory]
    [InlineData(RsaOaepHash.Sha256, 0x02)]
    [InlineData(RsaOaepHash.Sha384, 0x03)]
    [InlineData(RsaOaepHash.Sha512, 0x04)]
    public void ToWireByte_MatchesTheSpecification(RsaOaepHash oaepHash, byte expected) =>
        Assert.Equal(expected, RsaOaepHashWire.ToWireByte(oaepHash));

    [Theory]
    [InlineData(0x02, RsaOaepHash.Sha256)]
    [InlineData(0x03, RsaOaepHash.Sha384)]
    [InlineData(0x04, RsaOaepHash.Sha512)]
    public void FromWireByte_MatchesTheSpecification(byte value, RsaOaepHash expected) =>
        Assert.Equal(expected, RsaOaepHashWire.FromWireByte(value));

    [Theory]
    [InlineData(RsaOaepHash.Sha256)]
    [InlineData(RsaOaepHash.Sha384)]
    [InlineData(RsaOaepHash.Sha512)]
    public void TheMappingRoundTrips(RsaOaepHash oaepHash) =>
        Assert.Equal(oaepHash, RsaOaepHashWire.FromWireByte(RsaOaepHashWire.ToWireByte(oaepHash)));

    /// <summary>
    /// The hazard this type exists for: <see cref="RsaOaepHash"/> is unnumbered, so one of its members is
    /// <c>0</c> — and <c>0x00</c> is never a valid wire byte. A cast would therefore emit a byte no reader
    /// accepts, and shift every other value by one.
    /// </summary>
    [Fact]
    public void OneHashHasNumericValueZero_SoACastCannotProduceValidWireBytes()
    {
        int[] numericValues = Enum.GetValues<RsaOaepHash>().Select(value => (int)value).ToArray();

        Assert.Contains(0, numericValues);
        Assert.DoesNotContain(0, new[]
        {
            (int)RsaOaepHashWire.Sha1Byte,
            (int)RsaOaepHashWire.Sha256Byte,
            (int)RsaOaepHashWire.Sha384Byte,
            (int)RsaOaepHashWire.Sha512Byte,
        });
    }

    /// <summary>
    /// The wire bytes follow <see cref="RsaOaepHash"/>'s declaration order, one-based. That is what makes
    /// enabling SHA-1 later an un-reservation rather than a renumbering, so it is worth asserting rather
    /// than leaving to the mapping tables above.
    /// </summary>
    [Fact]
    public void TheWireBytesFollowTheEnumDeclarationOrderOneBased()
    {
        RsaOaepHash[] declared = Enum.GetValues<RsaOaepHash>();

        Assert.Equal<RsaOaepHash[]>(
            [RsaOaepHash.Sha1, RsaOaepHash.Sha256, RsaOaepHash.Sha384, RsaOaepHash.Sha512],
            declared);

        Assert.Equal(0x01, RsaOaepHashWire.Sha1Byte);
        Assert.Equal(0x02, RsaOaepHashWire.Sha256Byte);
        Assert.Equal(0x03, RsaOaepHashWire.Sha384Byte);
        Assert.Equal(0x04, RsaOaepHashWire.Sha512Byte);
    }

    // --- SHA-1: numbered, reserved, and rejected in both directions ------------------------------

    /// <summary>
    /// No writer can emit the reserved byte, however it reaches <see cref="RsaOaepHashWire.ToWireByte"/> —
    /// which is what keeps <c>0x01</c> unreachable from the write path (<c>docs/format.md</c> §10).
    /// </summary>
    [Fact]
    public void ToWireByte_ThrowsArgumentOutOfRange_ForSha1()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => RsaOaepHashWire.ToWireByte(RsaOaepHash.Sha1));

        Assert.Equal("oaepHash", exception.ParamName);
    }

    [Fact]
    public void ValidateArgument_ThrowsArgumentOutOfRange_ForSha1()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => RsaOaepHashWire.ValidateArgument(RsaOaepHash.Sha1, "theParameter"));

        Assert.Equal("theParameter", exception.ParamName);
    }

    /// <summary>
    /// The reserved byte is rejected on read too, and its message says <i>reserved</i> rather than
    /// <i>undefined</i> — the two are different states (§10) and a reader that conflates them would make
    /// the eventual un-reservation harder to reason about.
    /// </summary>
    [Fact]
    public void FromWireByte_ThrowsFormat_ForTheReservedSha1Byte()
    {
        DataEncryptionFormatException exception = Assert.Throws<DataEncryptionFormatException>(
            () => RsaOaepHashWire.FromWireByte(RsaOaepHashWire.Sha1Byte));

        Assert.Contains("reserved", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SHA-1", exception.Message, StringComparison.Ordinal);
    }

    // --- Everything else ------------------------------------------------------------------------

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0x10)]
    [InlineData(0x7F)]
    [InlineData(0x80)]
    [InlineData(0xFF)]
    public void FromWireByte_ThrowsFormat_ForAnUndefinedByte(byte value) =>
        Assert.Throws<DataEncryptionFormatException>(() => RsaOaepHashWire.FromWireByte(value));

    /// <summary>
    /// The whole byte range, so no value outside <c>0x02</c>–<c>0x04</c> parses — the sweep the theory
    /// above only samples.
    /// </summary>
    [Fact]
    public void FromWireByte_AcceptsExactlyThreeBytesOutOfTheWholeRange()
    {
        for (int value = 0x00; value <= 0xFF; value++)
        {
            bool accepted = value is RsaOaepHashWire.Sha256Byte
                or RsaOaepHashWire.Sha384Byte
                or RsaOaepHashWire.Sha512Byte;

            if (accepted)
            {
                RsaOaepHashWire.FromWireByte((byte)value);
                continue;
            }

            Assert.Throws<DataEncryptionFormatException>(
                () => RsaOaepHashWire.FromWireByte((byte)value));
        }
    }

    [Fact]
    public void ToWireByte_ThrowsArgumentOutOfRange_ForAnUndefinedHash() =>
        Assert.Throws<ArgumentOutOfRangeException>(
            () => RsaOaepHashWire.ToWireByte((RsaOaepHash)99));

    [Fact]
    public void ValidateArgument_ThrowsArgumentOutOfRange_ForAnUndefinedHash() =>
        Assert.Throws<ArgumentOutOfRangeException>(
            () => RsaOaepHashWire.ValidateArgument((RsaOaepHash)99, "oaepHash"));

    [Theory]
    [InlineData(RsaOaepHash.Sha256)]
    [InlineData(RsaOaepHash.Sha384)]
    [InlineData(RsaOaepHash.Sha512)]
    public void ValidateArgument_AcceptsTheThreeSupportedHashes(RsaOaepHash oaepHash) =>
        RsaOaepHashWire.ValidateArgument(oaepHash, "oaepHash");
}
