using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Covers <see cref="CryptoHelpers"/> — the constant-time comparison behind key confirmation, and the
/// buffer-zeroing helper every <c>finally</c> in the library calls.
/// </summary>
public sealed class CryptoHelpersTests
{
    // --- FixedTimeEquals -----------------------------------------------------------------------

    [Fact]
    public void FixedTimeEquals_IsTrue_ForEqualArrays()
    {
        byte[] left = FormatTestData.Sequence(0x00, 16);
        byte[] right = FormatTestData.Sequence(0x00, 16);

        Assert.True(CryptoHelpers.FixedTimeEquals(left, right));
    }

    [Fact]
    public void FixedTimeEquals_IsFalse_WhenTheFirstByteDiffers()
    {
        byte[] left = FormatTestData.Sequence(0x00, 16);
        byte[] right = FormatTestData.WithByteAt(left, 0, 0xFF);

        Assert.False(CryptoHelpers.FixedTimeEquals(left, right));
    }

    [Fact]
    public void FixedTimeEquals_IsFalse_WhenTheLastByteDiffers()
    {
        byte[] left = FormatTestData.Sequence(0x00, 16);
        byte[] right = FormatTestData.WithByteAt(left, left.Length - 1, 0xFF);

        Assert.False(CryptoHelpers.FixedTimeEquals(left, right));
    }

    /// <summary>A single flipped bit anywhere must be enough — the comparison is not a prefix check.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(64)]
    [InlineData(127)]
    public void FixedTimeEquals_IsFalse_ForASingleFlippedBit(int bitIndex)
    {
        byte[] left = FormatTestData.Sequence(0x00, 16);
        byte[] right = FormatTestData.WithFlippedBit(left, bitIndex);

        Assert.False(CryptoHelpers.FixedTimeEquals(left, right));
    }

    [Fact]
    public void FixedTimeEquals_IsFalse_ForDifferentLengths()
    {
        byte[] left = FormatTestData.Sequence(0x00, 16);
        byte[] right = FormatTestData.Sequence(0x00, 15);

        Assert.False(CryptoHelpers.FixedTimeEquals(left, right));
        Assert.False(CryptoHelpers.FixedTimeEquals(right, left));
    }

    [Fact]
    public void FixedTimeEquals_IsTrue_ForTwoEmptyArrays() =>
        Assert.True(CryptoHelpers.FixedTimeEquals([], []));

    [Fact]
    public void FixedTimeEquals_IsFalse_WhenEitherSideIsNull()
    {
        byte[] value = FormatTestData.Sequence(0x00, 16);

        Assert.False(CryptoHelpers.FixedTimeEquals(null, value));
        Assert.False(CryptoHelpers.FixedTimeEquals(value, null));
        Assert.False(CryptoHelpers.FixedTimeEquals(null, null));
    }

    // --- Clear ---------------------------------------------------------------------------------

    [Fact]
    public void Clear_ZeroesEveryBuffer()
    {
        byte[] first = FormatTestData.Sequence(0x01, 32);
        byte[] second = FormatTestData.Sequence(0x40, 16);

        CryptoHelpers.Clear(first, second);

        Assert.All(first, b => Assert.Equal(0, b));
        Assert.All(second, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Clear_IgnoresNullAndEmptyBuffers()
    {
        byte[] buffer = FormatTestData.Sequence(0x01, 8);

        // Must not throw: the library calls this from finally blocks where a buffer may never have
        // been assigned.
        CryptoHelpers.Clear(null, [], buffer);

        Assert.All(buffer, b => Assert.Equal(0, b));
    }

    [Fact]
    public void Clear_IgnoresANullBufferArray() => CryptoHelpers.Clear(null!);
}
