using Enigma.Core.Hashing.Hmac;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Pins the key-confirmation derivation of <c>docs/format.md</c> §6 against a hard-coded vector.
/// </summary>
/// <remarks>
/// <para>
/// <b>A round-trip test would not be enough here.</b> Swapping the arguments of
/// <c>IHmacService.ComputeHmac(data, key)</c>, MAC-ing under <c>K</c> instead of the derived
/// <c>kcKey</c>, or taking the rightmost 16 bytes instead of the leftmost all produce constructions
/// that verify their own output perfectly and match no specification. Only a vector computed
/// independently of this code catches them — the expected tags below were produced with Python's
/// <c>hmac</c> module from the formulae in §6.
/// </para>
/// </remarks>
public sealed class KeyConfirmationTests
{
    /// <summary>
    /// The 37 header bytes preceding the tag in the fixed PBKDF2 vector: magic <c>EC DE</c>, method
    /// <c>0x01</c>, version <c>0x10</c>, cipher <c>0x01</c>, nonce <c>00</c>–<c>0B</c>, salt
    /// <c>10</c>–<c>1F</c>, and 600,000 iterations as <c>C0 27 09 00</c>.
    /// </summary>
    private static readonly byte[] HeaderBytesBeforeTag =
    [
        0xEC, 0xDE, 0x01, 0x10, 0x01,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0xC0, 0x27, 0x09, 0x00,
    ];

    /// <summary>
    /// The tag those 37 bytes produce under <c>K = 00 01 … 1F</c>. Computed independently of this
    /// library.
    /// </summary>
    private static readonly byte[] ExpectedTag =
    [
        0xA5, 0x80, 0xEB, 0xC0, 0x66, 0x43, 0x3D, 0x13,
        0xF6, 0x42, 0x29, 0x24, 0x5C, 0x69, 0xC4, 0xE3,
    ];

    private static IHmacService Hmac() => FormatTestData.HmacSha256();

    [Fact]
    public void ComputeTag_MatchesTheHardCodedVector() =>
        Assert.Equal(ExpectedTag, KeyConfirmation.ComputeTag(Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag));

    [Fact]
    public void ComputeTag_Returns16Bytes() =>
        Assert.Equal(
            DataEncryptionDefaults.KeyConfirmationTagSizeBytes,
            KeyConfirmation.ComputeTag(Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag).Length);

    [Fact]
    public void ComputeTag_IsDeterministic() =>
        Assert.Equal(
            KeyConfirmation.ComputeTag(Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag),
            KeyConfirmation.ComputeTag(Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag));

    [Fact]
    public void Verify_AcceptsTheRightTag() =>
        Assert.True(KeyConfirmation.Verify(
            Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag, ExpectedTag));

    /// <summary>Every single-bit change to the tag must be rejected — all 128 of them.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(126)]
    [InlineData(127)]
    public void Verify_RejectsASingleBitFlippedTag(int bitIndex) =>
        Assert.False(KeyConfirmation.Verify(
            Hmac(),
            FormatTestData.DataKey(),
            HeaderBytesBeforeTag,
            FormatTestData.WithFlippedBit(ExpectedTag, bitIndex)));

    [Fact]
    public void Verify_RejectsEveryBitFlippedTag()
    {
        for (int bitIndex = 0; bitIndex < ExpectedTag.Length * 8; bitIndex++)
        {
            Assert.False(KeyConfirmation.Verify(
                Hmac(),
                FormatTestData.DataKey(),
                HeaderBytesBeforeTag,
                FormatTestData.WithFlippedBit(ExpectedTag, bitIndex)));
        }
    }

    /// <summary>The wrong-credential case: a different data key must not confirm.</summary>
    [Fact]
    public void Verify_RejectsADifferentDataKey()
    {
        byte[] otherKey = FormatTestData.WithFlippedBit(FormatTestData.DataKey(), 0);

        Assert.False(KeyConfirmation.Verify(Hmac(), otherKey, HeaderBytesBeforeTag, ExpectedTag));
    }

    /// <summary>
    /// The tag covers the header, so editing any header byte invalidates it. This is the second line of
    /// defence behind the GCM AAD.
    /// </summary>
    /// <remarks>
    /// The edit is a bit flip rather than a fixed replacement byte: several of these offsets already
    /// hold <c>0x00</c> in this vector, so overwriting them with zero would be no edit at all and the
    /// test would assert nothing.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(17)]
    [InlineData(33)]
    [InlineData(36)]
    public void Verify_RejectsAnEditedHeader(int offset) =>
        Assert.False(KeyConfirmation.Verify(
            Hmac(),
            FormatTestData.DataKey(),
            FormatTestData.WithFlippedBit(HeaderBytesBeforeTag, offset * 8),
            ExpectedTag));

    /// <summary>Every byte of the header is covered, not merely the fields a hand-picked list names.</summary>
    [Fact]
    public void Verify_RejectsAnEditAtEveryHeaderOffset()
    {
        for (int offset = 0; offset < HeaderBytesBeforeTag.Length; offset++)
        {
            Assert.False(KeyConfirmation.Verify(
                Hmac(),
                FormatTestData.DataKey(),
                FormatTestData.WithFlippedBit(HeaderBytesBeforeTag, offset * 8),
                ExpectedTag));
        }
    }

    [Fact]
    public void Verify_RejectsATagOfTheWrongLength() =>
        Assert.False(KeyConfirmation.Verify(
            Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag, FormatTestData.Sequence(0x00, 15)));

    /// <summary>
    /// A different header of the same length must produce a different tag — the tag is a MAC over the
    /// header, not a constant derived from the key alone.
    /// </summary>
    [Fact]
    public void ComputeTag_DependsOnTheHeaderBytes()
    {
        byte[] tag = KeyConfirmation.ComputeTag(Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag);
        byte[] otherTag = KeyConfirmation.ComputeTag(
            Hmac(), FormatTestData.DataKey(), FormatTestData.WithFlippedBit(HeaderBytesBeforeTag, 40));

        Assert.NotEqual(tag, otherTag);
    }

    /// <summary>
    /// And a different key must produce a different tag over the same header — the other half of the
    /// same property.
    /// </summary>
    [Fact]
    public void ComputeTag_DependsOnTheDataKey()
    {
        byte[] tag = KeyConfirmation.ComputeTag(Hmac(), FormatTestData.DataKey(), HeaderBytesBeforeTag);
        byte[] otherTag = KeyConfirmation.ComputeTag(
            Hmac(), FormatTestData.WithFlippedBit(FormatTestData.DataKey(), 255), HeaderBytesBeforeTag);

        Assert.NotEqual(tag, otherTag);
    }

    /// <summary>
    /// The caller's data key must survive the call: the derived confirmation key is cleared internally,
    /// but <c>K</c> belongs to the caller and is still needed for the payload.
    /// </summary>
    [Fact]
    public void ComputeTag_DoesNotClearTheCallersDataKey()
    {
        byte[] dataKey = FormatTestData.DataKey();

        KeyConfirmation.ComputeTag(Hmac(), dataKey, HeaderBytesBeforeTag);

        Assert.Equal(FormatTestData.DataKey(), dataKey);
    }

    /// <summary>And the header bytes must survive it too — they are about to become the GCM AAD.</summary>
    [Fact]
    public void ComputeTag_DoesNotModifyTheHeaderBytes()
    {
        byte[] header = (byte[])HeaderBytesBeforeTag.Clone();

        KeyConfirmation.ComputeTag(Hmac(), FormatTestData.DataKey(), header);

        Assert.Equal(HeaderBytesBeforeTag, header);
    }
}
