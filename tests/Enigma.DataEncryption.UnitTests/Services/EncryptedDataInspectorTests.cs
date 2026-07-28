using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The inspector: what it reports for each of the four header shapes, what it deliberately does not
/// report, and — the part with real consequences — where it leaves the stream.
/// </summary>
/// <remarks>
/// <para>
/// The headers come from <see cref="FormatTestData"/> rather than from a real encryption, so a shape can
/// be built without a credential and the expected field values are the fixed ones PHASE01 already pinned.
/// The suites that need containers a service actually wrote use <see cref="ContainerMethodHarness"/>
/// instead — both paths are exercised below.
/// </para>
/// <para>
/// The inspector is the one service with no dependencies at all, which is why it takes no factories:
/// parsing a header needs the format rules and nothing else.
/// </para>
/// </remarks>
public sealed class EncryptedDataInspectorTests
{
    private static readonly IEncryptedDataInspector Inspector = new EncryptedDataInspector();

    /// <summary>
    /// Reads a header with the test's own cancellation token, so every call site below stays readable.
    /// </summary>
    /// <param name="input">The container stream.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <returns>The parsed header.</returns>
    private static Task<EncryptedDataHeader> ReadAsync(Stream input, DataEncryptionLimits? limits = null) =>
        Inspector.ReadHeaderAsync(input, limits, TestContext.Current.CancellationToken);

    /// <summary>The four header shapes.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<HeaderShape> Shapes() =>
        [HeaderShape.Pbkdf2, HeaderShape.Argon2, HeaderShape.Rsa, HeaderShape.MLKem];

    // --- What it reports ---------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task TheCommonFieldsAreReportedForEveryShape(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape, Cipher.Serpent256Gcm);
        using MemoryStream input = new(header, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(FormatTestData.MethodOf(shape), parsed.Method);
        Assert.Equal(DataEncryptionDefaults.FormatVersion, parsed.FormatVersion);
        Assert.Equal(Cipher.Serpent256Gcm, parsed.Cipher);
        Assert.Equal(FormatTestData.HeaderLengthOf(shape), parsed.HeaderLength);
    }

    /// <summary>
    /// <see cref="EncryptedDataHeader.HeaderLength"/> is documented as the offset of the first payload
    /// byte, so on a non-seekable stream it must equal exactly how far the read got.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task TheReportedHeaderLengthIsTheOffsetOfTheFirstPayloadByte(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        byte[] container = [.. header, 0xAA, 0xBB, 0xCC];
        using MemoryStream input = new(container, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(header.Length, parsed.HeaderLength);
        Assert.Equal(0xAA, container[parsed.HeaderLength]);
    }

    [Fact]
    public async Task ThePbkdf2IterationCountIsReported()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);
        using MemoryStream input = new(header, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(DataEncryptionDefaults.Pbkdf2Iterations, parsed.Pbkdf2Iterations);
    }

    [Fact]
    public async Task TheThreeArgon2CostsAreReported()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2);
        using MemoryStream input = new(header, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(DataEncryptionDefaults.Argon2Iterations, parsed.Argon2Iterations);
        Assert.Equal(DataEncryptionDefaults.Argon2MemorySizeKb, parsed.Argon2MemorySizeKb);
        Assert.Equal(DataEncryptionDefaults.Argon2DegreeOfParallelism, parsed.Argon2DegreeOfParallelism);
    }

    [Fact]
    public async Task TheWrappedKeyLengthIsReported()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);
        using MemoryStream input = new(header, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(FormatTestData.RsaWrappedKeyLength, parsed.WrappedKeyLength);
    }

    [Fact]
    public async Task TheParameterSetAndEncapsulationLengthAreReported()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem);
        using MemoryStream input = new(header, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(FormatTestData.MLKemFixtureParameterSet, parsed.MLKemParameterSet);
        Assert.Equal(FormatTestData.MLKemEncapsulationLength, parsed.EncapsulationLength);
    }

    /// <summary>
    /// Every property that does not belong to the parsed method is <see langword="null"/>. A reader
    /// switching on <see cref="EncryptedDataHeader.Method"/> relies on that: a stale value carried over
    /// from another shape would be indistinguishable from a real one.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task PropertiesThatDoNotApplyToTheMethodAreNull(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        using MemoryStream input = new(header, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        if (shape != HeaderShape.Pbkdf2) Assert.Null(parsed.Pbkdf2Iterations);

        if (shape != HeaderShape.Argon2)
        {
            Assert.Null(parsed.Argon2Iterations);
            Assert.Null(parsed.Argon2MemorySizeKb);
            Assert.Null(parsed.Argon2DegreeOfParallelism);
        }

        if (shape != HeaderShape.Rsa) Assert.Null(parsed.WrappedKeyLength);

        if (shape != HeaderShape.MLKem)
        {
            Assert.Null(parsed.MLKemParameterSet);
            Assert.Null(parsed.EncapsulationLength);
        }
    }

    // --- Real containers ---------------------------------------------------------------------------

    /// <summary>
    /// Against containers the services actually wrote, not hand-built headers — and with the cipher
    /// swept, since the cipher byte is the one algorithmic field a caller may want to inspect.
    /// </summary>
    public static TheoryData<ContainerMethodKind, Cipher> MethodsAndCiphers()
    {
        TheoryData<ContainerMethodKind, Cipher> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            foreach (Cipher cipher in ContainerMethodHarness.AllCiphers)
            {
                data.Add(kind, cipher);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task ARealContainerIsInspectedCorrectly(ContainerMethodKind kind, Cipher cipher)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] container = await harness.EncryptToBytesAsync(ContainerFixtures.Plaintext(128), cipher);
        using MemoryStream input = new(container, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(harness.Method, parsed.Method);
        Assert.Equal(cipher, parsed.Cipher);
        Assert.Equal(harness.HeaderLength, parsed.HeaderLength);
        Assert.Equal(DataEncryptionDefaults.FormatVersion, parsed.FormatVersion);
    }

    /// <summary>
    /// The header ML-KEM's default parameter set produces is reported as ML-KEM-1024 — the same default
    /// PHASE04 pinned from the raw bytes, now read back through the public inspector.
    /// </summary>
    [Fact]
    public async Task TheDefaultMLKemParameterSetIsReportedAsMLKem1024()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            MLKemTestData.GoldenPublicKey("1024"), ContainerFixtures.Plaintext(32));
        using MemoryStream input = new(container, writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(MLKemParameterSet.MLKem1024, parsed.MLKemParameterSet);
        Assert.Equal(MLKemTestData.EncapsulationLength1024, parsed.EncapsulationLength);
    }

    /// <summary>
    /// The whole point of the inspector: inspect, then hand the same stream to the decryption service.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnInspectedSeekableStreamCanStillBeDecrypted(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(256);
        byte[] container = await harness.EncryptToBytesAsync(plaintext);

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        EncryptedDataHeader parsed = await ReadAsync(input);
        await harness.DecryptAsync(input, output, null, null, TestContext.Current.CancellationToken);

        Assert.Equal(harness.Method, parsed.Method);
        Assert.Equal(plaintext, output.ToArray());
    }

    /// <summary>The four methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<ContainerMethodKind> Methods() => [.. ContainerMethodHarness.All];

    // --- Stream position ---------------------------------------------------------------------------

    /// <summary>
    /// A seekable stream comes back exactly where it was — including when it did not start at zero, which
    /// is the case a "rewind to 0" implementation would get wrong.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    public async Task ASeekableStreamsPositionIsRestored(int leadingBytes)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);
        byte[] content = [.. new byte[leadingBytes], .. header, 0x01, 0x02];

        using MemoryStream input = new(content, writable: false);
        input.Position = leadingBytes;

        await ReadAsync(input);

        Assert.Equal(leadingBytes, input.Position);
    }

    /// <summary>
    /// And it is restored on failure too. A caller probing a file it is unsure about should get its
    /// stream back untouched, not half-consumed.
    /// </summary>
    [Fact]
    public async Task ASeekableStreamsPositionIsRestoredAfterAFormatError()
    {
        byte[] notAContainer = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        using MemoryStream input = new(notAContainer, writable: false);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(() => ReadAsync(input));

        Assert.Equal(0, input.Position);
    }

    /// <summary>The same, for a truncation deep inside the header rather than a bad magic.</summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task ASeekableStreamsPositionIsRestoredAfterATruncatedHeader(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        using MemoryStream input = new(header[..^1], writable: false);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(() => ReadAsync(input));

        Assert.Equal(0, input.Position);
    }

    /// <summary>
    /// A non-seekable stream is left at the first payload byte — documented, and the reason a caller who
    /// needs both the header and a decrypt must buffer the stream itself.
    /// </summary>
    [Theory]
    [MemberData(nameof(Shapes))]
    public async Task ANonSeekableStreamIsLeftAtThePayload(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        byte[] container = [.. header, 0xAA, 0xBB];
        ForwardOnlyStream input = new(container, maxChunk: 3);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(header.Length, parsed.HeaderLength);

        // The next byte available is the first payload byte, so exactly the header was consumed.
        byte[] next = new byte[1];
        Assert.Equal(1, await input.ReadAsync(next, 0, 1, CancellationToken.None));
        Assert.Equal(0xAA, next[0]);
    }

    /// <summary>
    /// A non-seekable container decrypts straight after being inspected: the stream is already sitting on
    /// the payload, which is the only thing the inspector can usefully leave behind. This is the
    /// documented workflow, so it is asserted rather than left implied.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ANonSeekableStreamCannotBeReInspected(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] container = await harness.EncryptToBytesAsync(ContainerFixtures.Plaintext(64));
        ForwardOnlyStream input = new(container, maxChunk: 64);

        await ReadAsync(input);

        // The header is gone from the stream, so a second read sees the payload as a header.
        await Assert.ThrowsAsync<DataEncryptionFormatException>(() => ReadAsync(input));
    }

    // --- Limits, arguments and cancellation --------------------------------------------------------

    /// <summary>
    /// The inspector applies the same bounds as a decrypt, so "will this container be expensive to open"
    /// can be answered before committing to opening it.
    /// </summary>
    [Fact]
    public async Task TightenedLimitsAreAppliedByTheInspectorToo()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);
        DataEncryptionLimits tightened = new() { MaxPbkdf2Iterations = 1_000 };

        using MemoryStream tight = new(header, writable: false);
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => ReadAsync(tight, tightened));

        // The very same container parses under the defaults.
        using MemoryStream loose = new(header, writable: false);
        EncryptedDataHeader parsed = await ReadAsync(loose);
        Assert.Equal(DataEncryptionDefaults.Pbkdf2Iterations, parsed.Pbkdf2Iterations);
    }

    /// <summary>
    /// A null stream faults the call rather than the returned task: validation is synchronous, the same
    /// convention the four encryption services follow.
    /// </summary>
    [Fact]
    public void ANullStreamThrowsSynchronously()
    {
        ArgumentNullException exception = Assert.Throws<ArgumentNullException>(
            () => { _ = Inspector.ReadHeaderAsync(null!, null, CancellationToken.None); });

        Assert.Equal("input", exception.ParamName);
    }

    [Fact]
    public async Task ACancelledTokenIsObserved()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2);
        using MemoryStream input = new(header, writable: false);
        using CancellationTokenSource cancellation = new();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Inspector.ReadHeaderAsync(input, null, cancellation.Token));
    }

    /// <summary>
    /// The stream is never disposed — the caller owns it. Reading from a disposed
    /// <see cref="MemoryStream"/> throws, so a successful read is the assertion; that it yields the first
    /// magic byte says the position was restored as well.
    /// </summary>
    [Fact]
    public async Task TheStreamIsNotDisposed()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2);
        using MemoryStream input = new(header, writable: false);

        await ReadAsync(input);

        byte[] next = new byte[1];
        Assert.Equal(1, input.Read(next, 0, 1));
        Assert.Equal(0xEC, next[0]);
    }

    // --- Malformed input ---------------------------------------------------------------------------

    /// <summary>
    /// Every truncation of every shape, through the public inspector. Only
    /// <see cref="DataEncryptionFormatException"/> is admissible here — not
    /// <see cref="DataDecryptionException"/> — because the inspector uses no credential and reads no
    /// payload, which is what its XML documentation promises.
    /// </summary>
    public static TheoryData<HeaderShape, int> EveryTruncation()
    {
        TheoryData<HeaderShape, int> data = [];
        foreach (HeaderShape shape in new[]
                 {
                     HeaderShape.Pbkdf2, HeaderShape.Argon2, HeaderShape.Rsa, HeaderShape.MLKem,
                 })
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
    public async Task ATruncatedHeaderIsAlwaysAFormatErrorAndNothingElse(HeaderShape shape, int truncateTo)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        using MemoryStream input = new(header[..truncateTo], writable: false);

        Exception? exception = await Record.ExceptionAsync(() => ReadAsync(input));

        Assert.NotNull(exception);
        Assert.IsType<DataEncryptionFormatException>(exception);
    }

    /// <summary>
    /// Every value of the method byte, the version byte and the ML-KEM parameter-set byte that the
    /// inspector must refuse. It accepts any of the four methods, so only genuinely undefined values are
    /// swept here.
    /// </summary>
    public static TheoryData<HeaderShape, int, byte> UndefinedBytes()
    {
        TheoryData<HeaderShape, int, byte> data = [];

        // Method byte: 0x00, the reserved 0x05, and everything above it.
        data.Add(HeaderShape.Pbkdf2, 2, 0x00);
        for (int value = 0x05; value <= 0xFF; value++)
        {
            data.Add(HeaderShape.Pbkdf2, 2, (byte)value);
        }

        // Version byte: the whole reserved legacy range and a spread above 0x10.
        for (int value = 0x00; value <= 0x0F; value++)
        {
            data.Add(HeaderShape.Argon2, 3, (byte)value);
        }

        foreach (byte value in new byte[] { 0x11, 0x12, 0x1F, 0x20, 0x40, 0x7F, 0x80, 0xC0, 0xFE, 0xFF })
        {
            data.Add(HeaderShape.Argon2, 3, value);
        }

        // Cipher byte.
        foreach (byte value in new byte[] { 0x00, 0x05, 0x06, 0x10, 0x7F, 0x80, 0xFE, 0xFF })
        {
            data.Add(HeaderShape.Rsa, 4, value);
        }

        // ML-KEM parameter-set byte: 0x00 matters most — the wire encoding is 1-based so that a
        // zero-filled header cannot parse.
        data.Add(HeaderShape.MLKem, 5, 0x00);
        for (int value = 0x04; value <= 0xFF; value++)
        {
            data.Add(HeaderShape.MLKem, 5, (byte)value);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(UndefinedBytes))]
    public async Task AnUndefinedHeaderByteIsAlwaysAFormatErrorAndNothingElse(
        HeaderShape shape,
        int offset,
        byte value)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        using MemoryStream input = new(FormatTestData.WithByteAt(header, offset, value), writable: false);

        Exception? exception = await Record.ExceptionAsync(() => ReadAsync(input));

        Assert.NotNull(exception);
        Assert.IsType<DataEncryptionFormatException>(exception);
    }

    /// <summary>
    /// An edited-but-valid cipher byte parses and is reported as edited: catching that is the AAD's job at
    /// decryption time, not the inspector's, and the inspector has no key to check it with.
    /// </summary>
    [Theory]
    [InlineData(Cipher.Twofish256Gcm)]
    [InlineData(Cipher.Serpent256Gcm)]
    [InlineData(Cipher.Camellia256Gcm)]
    public async Task AnEditedButValidCipherByteIsReportedAsRead(Cipher edited)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2, Cipher.Aes256Gcm);
        using MemoryStream input = new(
            FormatTestData.WithByteAt(header, 4, (byte)edited), writable: false);

        EncryptedDataHeader parsed = await ReadAsync(input);

        Assert.Equal(edited, parsed.Cipher);
    }

    [Fact]
    public async Task AZeroLengthStreamIsAFormatError()
    {
        using MemoryStream input = new([], writable: false);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(() => ReadAsync(input));
    }

    [Fact]
    public async Task AOneByteStreamIsAFormatError()
    {
        using MemoryStream input = new([0xEC], writable: false);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(() => ReadAsync(input));
    }
}
