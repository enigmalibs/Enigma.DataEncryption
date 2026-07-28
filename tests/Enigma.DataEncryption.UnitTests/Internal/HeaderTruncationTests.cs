using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Truncates every one of the five header shapes at <b>every</b> byte offset and asserts each one is
/// reported as <see cref="DataEncryptionFormatException"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the suite that pins the translation boundary. Enigma.Core's stream helpers throw
/// <see cref="IOException"/> when a stream ends early, and <see cref="InvalidOperationException"/> when a
/// length-value's length is out of range. Either escaping <see cref="HeaderReader"/> would leak an
/// implementation detail into the public contract of §9, so both must be gone by the time the reader
/// returns.
/// </para>
/// <para>
/// A generated matrix rather than a handful of hand-picked offsets: the interesting truncations are the
/// ones nobody thinks to write down — one byte into the magic, one byte short of a length field, one
/// byte short of the confirmation tag.
/// </para>
/// </remarks>
public sealed class HeaderTruncationTests
{
    /// <summary>Every (shape, length) pair from a zero-length stream to one byte short of complete.</summary>
    public static TheoryData<HeaderShape, int> EveryTruncation()
    {
        TheoryData<HeaderShape, int> data = [];
        foreach (HeaderShape shape in FormatTestData.AllShapes)
        {
            for (int length = 0; length < FormatTestData.HeaderLengthOf(shape); length++)
            {
                data.Add(shape, length);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryTruncation))]
    public async Task ATruncatedHeaderIsAFormatError(HeaderShape shape, int truncateTo)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        byte[] truncated = header[..truncateTo];

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(truncated, FormatTestData.MethodOf(shape)));
    }

    /// <summary>
    /// The same sweep with no expected method, which is the inspector's path — the outcome must not
    /// depend on whether a method was expected.
    /// </summary>
    [Theory]
    [MemberData(nameof(EveryTruncation))]
    public async Task ATruncatedHeaderIsAFormatErrorForTheInspectorPathToo(HeaderShape shape, int truncateTo)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(header[..truncateTo]));
    }

    /// <summary>
    /// Neither of Enigma.Core's exception types may escape: they are what the boundary exists to
    /// translate. Asserting the type is <see cref="DataEncryptionFormatException"/> already covers this,
    /// but the inner exception is checked too so the cause is not lost on the way.
    /// </summary>
    [Theory]
    [InlineData(HeaderShape.Pbkdf2, 40)]
    [InlineData(HeaderShape.Argon2, 50)]
    [InlineData(HeaderShape.Rsa, 100)]
    [InlineData(HeaderShape.MLKem, 200)]
    [InlineData(HeaderShape.Hybrid, 500)]
    public async Task TheUnderlyingIoExceptionIsPreservedAsTheInnerException(HeaderShape shape, int truncateTo)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(header[..truncateTo], FormatTestData.MethodOf(shape)));

        Assert.IsAssignableFrom<IOException>(exception.InnerException);
    }

    [Fact]
    public async Task AZeroLengthStreamIsAFormatError() =>
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync([]));

    [Fact]
    public async Task AOneByteStreamIsAFormatError() =>
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync([0xEC]));

    /// <summary>
    /// A stream that ends between the length field and the variable-length value it announces: the
    /// length is in range, so the failure comes from the read that follows it.
    /// </summary>
    [Fact]
    public async Task AWrappedKeyShorterThanItsLengthFieldIsAFormatError()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);

        // Announce 4,096 bytes — within the cap — while supplying only 256.
        byte[] patched = FormatTestData.WithInt32At(header, 17, 4_096);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(patched, EncryptionMethod.Rsa));
    }

    [Fact]
    public async Task AnEncapsulationShorterThanItsLengthFieldIsAFormatError()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem);
        byte[] patched = FormatTestData.WithInt32At(header, 18, 4_096);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => FormatTestData.ReadHeaderAsync(patched, EncryptionMethod.MLKem));
    }

    /// <summary>
    /// A truncated header must never surface as an unhandled indexing or reference error — the failure
    /// mode a hand-rolled parser falls into. Asserting the exact type across the whole sweep is what
    /// rules that out; this test states the intent explicitly for the shapes' boundary offsets.
    /// </summary>
    [Theory]
    [MemberData(nameof(BoundaryTruncations))]
    public async Task ATruncatedHeaderNeverThrowsAnIndexingOrReferenceError(HeaderShape shape, int truncateTo)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);

        Exception? exception = await Record.ExceptionAsync(
            () => FormatTestData.ReadHeaderAsync(header[..truncateTo], FormatTestData.MethodOf(shape)));

        Assert.NotNull(exception);
        Assert.IsType<DataEncryptionFormatException>(exception);
        Assert.IsNotType<NullReferenceException>(exception);
        Assert.IsNotType<IndexOutOfRangeException>(exception);
        Assert.IsNotType<ArgumentOutOfRangeException>(exception);
        Assert.IsNotType<OutOfMemoryException>(exception);
    }

    /// <summary>The field boundaries of each shape — where an off-by-one in the parser would live.</summary>
    public static TheoryData<HeaderShape, int> BoundaryTruncations()
    {
        TheoryData<HeaderShape, int> data = [];

        foreach (int length in new[] { 0, 1, 2, 3, 4, 5, 16, 17, 32, 33, 36, 37, 52 })
        {
            data.Add(HeaderShape.Pbkdf2, length);
        }

        foreach (int length in new[] { 0, 5, 17, 33, 37, 41, 44, 45, 60 })
        {
            data.Add(HeaderShape.Argon2, length);
        }

        foreach (int length in new[] { 0, 5, 17, 20, 21, 22, 276, 277, 292 })
        {
            data.Add(HeaderShape.Rsa, length);
        }

        foreach (int length in new[] { 0, 5, 6, 18, 21, 22, 23, 789, 790, 805 })
        {
            data.Add(HeaderShape.MLKem, length);
        }

        // The hybrid's boundaries: the parameter-set byte, the nonce, the first length field, the first
        // value, the *second* length field at 22 + N = 278, the second value, and the tag at 26 + N + M.
        foreach (int length in new[] { 0, 5, 6, 18, 21, 22, 277, 278, 281, 282, 1_049, 1_050, 1_065 })
        {
            data.Add(HeaderShape.Hybrid, length);
        }

        return data;
    }

    /// <summary>
    /// A stream that ends early <b>mid-read</b> rather than at a clean offset — the case a parser that
    /// trusts a single <c>Read</c> call to fill its buffer would silently mis-handle.
    /// </summary>
    [Fact]
    public async Task AStreamThatEndsMidReadIsAFormatError()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);
        using MemoryStream input = new(header[..30], writable: false);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HeaderReader.ReadAsync(
                input, EncryptionMethod.Pbkdf2, DataEncryptionLimits.Default, CancellationToken.None));
    }
}
