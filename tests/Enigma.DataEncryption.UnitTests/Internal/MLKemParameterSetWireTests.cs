using System;
using System.Linq;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Pins the ML-KEM parameter-set wire encoding of <c>docs/format.md</c> §3.4 — the one place in this
/// library where an enum's numeric value and its wire byte deliberately differ.
/// </summary>
public sealed class MLKemParameterSetWireTests
{
    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, 0x01)]
    [InlineData(MLKemParameterSet.MLKem768, 0x02)]
    [InlineData(MLKemParameterSet.MLKem1024, 0x03)]
    public void ToWireByte_MatchesTheSpecification(MLKemParameterSet parameterSet, byte expected) =>
        Assert.Equal(expected, MLKemParameterSetWire.ToWireByte(parameterSet));

    [Theory]
    [InlineData(0x01, MLKemParameterSet.MLKem512)]
    [InlineData(0x02, MLKemParameterSet.MLKem768)]
    [InlineData(0x03, MLKemParameterSet.MLKem1024)]
    public void FromWireByte_MatchesTheSpecification(byte value, MLKemParameterSet expected) =>
        Assert.Equal(expected, MLKemParameterSetWire.FromWireByte(value));

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512)]
    [InlineData(MLKemParameterSet.MLKem768)]
    [InlineData(MLKemParameterSet.MLKem1024)]
    public void TheMappingRoundTrips(MLKemParameterSet parameterSet) =>
        Assert.Equal(
            parameterSet,
            MLKemParameterSetWire.FromWireByte(MLKemParameterSetWire.ToWireByte(parameterSet)));

    /// <summary>
    /// The hazard this type exists for: <see cref="MLKemParameterSet"/> is unnumbered, so one of its
    /// members is <c>0</c> — and <c>0x00</c> is never a valid wire byte. A cast would therefore emit a
    /// byte no reader accepts, and shift the other two by one.
    /// </summary>
    [Fact]
    public void OneParameterSetHasNumericValueZero_SoACastCannotProduceValidWireBytes()
    {
        int[] numericValues = Enum.GetValues<MLKemParameterSet>().Select(value => (int)value).ToArray();

        Assert.Contains(0, numericValues);
        Assert.DoesNotContain(0, new[]
        {
            (int)MLKemParameterSetWire.MLKem512Byte,
            (int)MLKemParameterSetWire.MLKem768Byte,
            (int)MLKemParameterSetWire.MLKem1024Byte,
        });
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x04)]
    [InlineData(0x10)]
    [InlineData(0xFF)]
    public void FromWireByte_ThrowsFormat_ForAnUndefinedByte(byte value) =>
        Assert.Throws<DataEncryptionFormatException>(() => MLKemParameterSetWire.FromWireByte(value));

    [Fact]
    public void ToWireByte_ThrowsArgumentOutOfRange_ForAnUndefinedParameterSet() =>
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MLKemParameterSetWire.ToWireByte((MLKemParameterSet)99));
}
