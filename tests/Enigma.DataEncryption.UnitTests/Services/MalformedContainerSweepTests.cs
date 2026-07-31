using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The cross-cutting malformed-input sweep: a generated matrix of corrupted and truncated containers,
/// driven through all five services, asserting that <b>every</b> outcome is one of the two container
/// exception types and never anything else.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this adds over the per-method failure suites.</b> Those assert the <i>expected</i> exception
/// for cases chosen per method. This one asserts the <i>admissible set</i> — exactly
/// <see cref="DataEncryptionFormatException"/> or <see cref="DataDecryptionException"/> — uniformly across
/// a matrix nobody wrote by hand. The distinction matters because the failure worth catching is not "the
/// wrong one of the two" but "something else entirely": an <see cref="IndexOutOfRangeException"/> from a
/// hand-rolled offset, an <see cref="OutOfMemoryException"/> from trusting a length field, or an
/// unwrapped Enigma.Core exception leaking BouncyCastle's shape into this library's contract.
/// </para>
/// <para>
/// <b>Which of the two is correct is deliberately not asserted here</b>, because for several cases the
/// answer is a documented judgement call rather than a derivation — an edited ML-KEM parameter-set byte
/// is indistinguishable from a caller supplying the wrong key, so <c>docs/format.md</c> §9 reports both as
/// <see cref="DataDecryptionException"/>. The per-method suites pin the specific type case by case; this
/// suite pins that the set is closed.
/// </para>
/// <para>
/// One container per method is written once and reused across every case, so the matrix costs a few
/// thousand header parses rather than a few thousand encryptions. The credentials are committed fixtures
/// (see <see cref="ContainerMethodHarness"/>), so the containers are the same from run to run.
/// </para>
/// </remarks>
public sealed class MalformedContainerSweepTests
{
    /// <summary>The payload length of the swept containers — enough that a truncation has something to cut.</summary>
    private const int PayloadLength = 256;

    private static readonly ConcurrentDictionary<ContainerMethodKind, Task<byte[]>> Containers = new();

    /// <summary>The five methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<ContainerMethodKind> Methods() => [.. ContainerMethodHarness.All];

    // --- Magic (§2.1) ------------------------------------------------------------------------------

    /// <summary>
    /// Both magic bytes, independently. A reader that checks only one of them accepts half the wrong files
    /// there are, so the two offsets are swept separately rather than as a pair.
    /// </summary>
    public static TheoryData<ContainerMethodKind, int, byte> MagicEdits()
    {
        TheoryData<ContainerMethodKind, int, byte> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            foreach (byte value in new byte[] { 0x00, 0xDE, 0xEB, 0xED, 0x7F, 0xFF })
            {
                data.Add(kind, 0, value);
            }

            foreach (byte value in new byte[] { 0x00, 0xEC, 0xDD, 0xDF, 0x7F, 0xFF })
            {
                data.Add(kind, 1, value);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(MagicEdits))]
    public async Task AWrongMagicByteIsAContainerError(ContainerMethodKind kind, int offset, byte value)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, FormatTestData.WithByteAt(container, offset, value));
    }

    // --- Method byte (§2.2) ------------------------------------------------------------------------

    /// <summary>
    /// <b>Every</b> method byte other than the service's own — all 255 of them, per method. That includes
    /// the four other defined methods (a container handed to the wrong service), none of which may be
    /// parsed as if it belonged here.
    /// </summary>
    public static TheoryData<ContainerMethodKind, byte> EveryForeignMethodByte()
    {
        TheoryData<ContainerMethodKind, byte> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            byte own = ContainerMethodHarness.MethodByteOf(kind);
            for (int value = 0x00; value <= 0xFF; value++)
            {
                if ((byte)value != own) data.Add(kind, (byte)value);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryForeignMethodByte))]
    public async Task AForeignOrUndefinedMethodByteIsAContainerError(ContainerMethodKind kind, byte value)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, FormatTestData.WithByteAt(container, 2, value));
    }

    // --- Format version (§2.3) --------------------------------------------------------------------

    /// <summary>
    /// The whole reserved legacy range <c>0x00</c>–<c>0x0F</c>, plus a spread above <c>0x10</c>. A legacy
    /// container must be refused cleanly rather than parsed as if it were this format.
    /// </summary>
    public static TheoryData<ContainerMethodKind, byte> VersionEdits()
    {
        TheoryData<ContainerMethodKind, byte> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            for (int value = 0x00; value <= 0x0F; value++)
            {
                data.Add(kind, (byte)value);
            }

            foreach (byte value in new byte[] { 0x11, 0x12, 0x1F, 0x20, 0x40, 0x7F, 0x80, 0xC0, 0xFE, 0xFF })
            {
                data.Add(kind, value);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(VersionEdits))]
    public async Task AVersionByteOtherThanThisFormatIsAContainerError(ContainerMethodKind kind, byte value)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, FormatTestData.WithByteAt(container, 3, value));
    }

    // --- Cipher byte (§2.4) -----------------------------------------------------------------------

    /// <summary>
    /// Undefined cipher bytes, and the three other <i>defined</i> ones. The defined ones are the more
    /// interesting half: they parse, so the edit has to be caught by the key-confirmation tag and the AAD
    /// rather than by the parser.
    /// </summary>
    public static TheoryData<ContainerMethodKind, byte> CipherEdits()
    {
        TheoryData<ContainerMethodKind, byte> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            foreach (byte value in new byte[]
                     {
                         0x00, 0x05, 0x06, 0x10, 0x7F, 0x80, 0xFE, 0xFF,   // undefined
                         0x02, 0x03, 0x04,                                  // defined, but not the one written
                     })
            {
                data.Add(kind, value);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CipherEdits))]
    public async Task AnEditedCipherByteIsAContainerError(ContainerMethodKind kind, byte value)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, FormatTestData.WithByteAt(container, 4, value));
    }

    // --- ML-KEM parameter set (§3.4) --------------------------------------------------------------

    /// <summary>
    /// Every parameter-set byte other than the one written — the two other valid ones included, since a
    /// switched parameter set changes what decapsulation expects rather than what the parser accepts. Swept
    /// for <b>both</b> methods that carry the byte, at the offset 5 they share.
    /// </summary>
    public static TheoryData<ContainerMethodKind, byte> EveryForeignParameterSetByte()
    {
        TheoryData<ContainerMethodKind, byte> data = [];
        byte own = MLKemTestData.WireByteOf(ContainerMethodHarness.KemParameterSet);
        foreach (ContainerMethodKind kind in ContainerMethodHarness.WithParameterSetByte)
        {
            for (int value = 0x00; value <= 0xFF; value++)
            {
                if ((byte)value != own) data.Add(kind, (byte)value);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryForeignParameterSetByte))]
    public async Task AnEditedMLKemParameterSetByteIsAContainerError(ContainerMethodKind kind, byte value)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(
            kind, FormatTestData.WithByteAt(container, MLKemTestData.ParameterSetOffset, value));
    }

    // --- RSA OAEP hash (§3.3) ----------------------------------------------------------------------

    /// <summary>
    /// Every OAEP-hash byte other than the one written — the two other valid ones included, since a
    /// switched hash changes what the unwrap expects rather than what the parser accepts, and the reserved
    /// <c>0x01</c> too. Only method <c>0x03</c> carries the byte; it shares offset 5 with the parameter set
    /// of the two methods above, which is why the sweep asserts a container error rather than a specific
    /// exception type — an edited selector may be caught by the parser, by OAEP or by the AAD depending on
    /// the value, and all three are documented outcomes.
    /// </summary>
    public static TheoryData<byte> EveryForeignOaepHashByte()
    {
        TheoryData<byte> data = [];
        for (int value = 0x00; value <= 0xFF; value++)
        {
            if ((byte)value != RsaOaepHashWire.Sha256Byte) data.Add((byte)value);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryForeignOaepHashByte))]
    public async Task AnEditedRsaOaepHashByteIsAContainerError(byte value)
    {
        byte[] container = await ContainerAsync(ContainerMethodKind.Rsa);

        await AssertContainerErrorAsync(
            ContainerMethodKind.Rsa,
            FormatTestData.WithByteAt(container, RsaTestData.OaepHashOffset, value));
    }

    // --- Cost and length fields (§8) ---------------------------------------------------------------

    /// <summary>
    /// Every <c>Int32</c> cost and length field of every method, at zero, negative, both integer extremes
    /// and one over its cap. <see cref="int.MaxValue"/> is the pointed case: it must cost a comparison to
    /// reject, not an allocation to survive.
    /// </summary>
    public static TheoryData<ContainerMethodKind, string, int, int> Int32FieldEdits()
    {
        TheoryData<ContainerMethodKind, string, int, int> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            foreach (ContainerMethodHarness.Int32HeaderField field in ContainerMethodHarness.For(kind).Int32Fields)
            {
                foreach (int value in new[] { 0, -1, int.MinValue, int.MaxValue, field.Cap + 1 })
                {
                    data.Add(kind, field.Name, field.Offset, value);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Int32FieldEdits))]
    public async Task AnOutOfRangeInt32FieldIsAContainerError(
        ContainerMethodKind kind,
        string fieldName,
        int offset,
        int value)
    {
        byte[] container = await ContainerAsync(kind);

        Assert.NotEmpty(fieldName);
        await AssertContainerErrorAsync(kind, FormatTestData.WithInt32At(container, offset, value));
    }

    /// <summary>
    /// A length field inside its cap but longer than the bytes that follow it. The cap alone does not save
    /// a reader here — it has to survive the read that the announced length then fails to satisfy.
    /// </summary>
    /// <summary>
    /// Every variable-length field of every method that has one — which for the hybrid means both of them,
    /// the only case where a second field's offset depends on a first field's value.
    /// </summary>
    public static TheoryData<ContainerMethodKind, int> EveryVariableLengthField()
    {
        TheoryData<ContainerMethodKind, int> data = [];
        foreach (ContainerMethodKind kind in
                 new[] { ContainerMethodKind.Rsa, ContainerMethodKind.MLKem, ContainerMethodKind.Hybrid })
        {
            foreach (ContainerMethodHarness.Int32HeaderField field in
                     ContainerMethodHarness.For(kind).Int32Fields)
            {
                data.Add(kind, field.Offset);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryVariableLengthField))]
    public async Task AnInCapLengthLongerThanTheStreamIsAContainerError(ContainerMethodKind kind, int offset)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, FormatTestData.WithInt32At(container, offset, 4_096));
    }

    // --- Truncation --------------------------------------------------------------------------------

    /// <summary>
    /// Every truncation offset inside every header shape — from the zero-length stream up to one byte
    /// short of a complete header. The interesting ones are the ones nobody writes down: one byte into the
    /// magic, one byte short of a length field, one byte short of the confirmation tag.
    /// </summary>
    public static TheoryData<ContainerMethodKind, int> EveryHeaderTruncation()
    {
        TheoryData<ContainerMethodKind, int> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            for (int length = 0; length < ContainerMethodHarness.HeaderLengthOf(kind); length++)
            {
                data.Add(kind, length);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryHeaderTruncation))]
    public async Task ATruncatedHeaderIsAContainerError(ContainerMethodKind kind, int truncateTo)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, container[..truncateTo]);
    }

    /// <summary>
    /// A complete header followed by a payload that is short, absent, or a byte too long. The header parses
    /// in every case, so these are the AEAD's to reject.
    /// </summary>
    public static TheoryData<ContainerMethodKind, int> PayloadTruncations()
    {
        TheoryData<ContainerMethodKind, int> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            int headerLength = ContainerMethodHarness.HeaderLengthOf(kind);

            // The payload is PayloadLength bytes of ciphertext plus a 16-byte GCM tag.
            foreach (int payloadBytes in new[] { 0, 1, 15, 16, 17, PayloadLength, PayloadLength + 15 })
            {
                data.Add(kind, headerLength + payloadBytes);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(PayloadTruncations))]
    public async Task ATruncatedPayloadIsAContainerError(ContainerMethodKind kind, int truncateTo)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, container[..truncateTo]);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ExtraBytesAfterThePayloadAreAContainerError(ContainerMethodKind kind)
    {
        byte[] container = await ContainerAsync(kind);

        await AssertContainerErrorAsync(kind, [.. container, 0x00]);
    }

    // --- Degenerate streams ------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AZeroLengthStreamIsAContainerError(ContainerMethodKind kind) =>
        await AssertContainerErrorAsync(kind, []);

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AOneByteStreamIsAContainerError(ContainerMethodKind kind) =>
        await AssertContainerErrorAsync(kind, [0xEC]);

    /// <summary>
    /// An all-zero buffer. Worth its own case because it is what an unwritten or sparsely allocated file
    /// looks like, and because a zero method byte, a zero version byte and a zero parameter-set byte are
    /// all invalid by construction.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnAllZeroStreamIsAContainerError(ContainerMethodKind kind) =>
        await AssertContainerErrorAsync(kind, new byte[1_024]);

    /// <summary>An all-<c>0xFF</c> buffer, for the same reason from the other end of the byte range.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnAllOnesStreamIsAContainerError(ContainerMethodKind kind)
    {
        byte[] ones = new byte[1_024];
        for (int i = 0; i < ones.Length; i++) ones[i] = 0xFF;

        await AssertContainerErrorAsync(kind, ones);
    }

    /// <summary>
    /// A container whose magic and method byte are right and whose every other byte is zero — a
    /// hand-crafted hostile header rather than a corrupted real one.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AZeroFilledHeaderBehindAValidPrefixIsAContainerError(ContainerMethodKind kind)
    {
        byte[] forged = new byte[ContainerMethodHarness.HeaderLengthOf(kind) + 64];
        forged[0] = 0xEC;
        forged[1] = 0xDE;
        forged[2] = ContainerMethodHarness.MethodByteOf(kind);

        await AssertContainerErrorAsync(kind, forged);
    }

    // --- The forbidden types, stated explicitly ----------------------------------------------------

    /// <summary>
    /// The same contract as <see cref="AssertContainerErrorAsync"/>, written out as the list of types that
    /// must never appear. Redundant with the assertions above by construction, and kept because the point
    /// of the whole suite is easier to read here than to infer from a positive type check.
    /// </summary>
    public static TheoryData<ContainerMethodKind, int> BoundaryTruncations()
    {
        TheoryData<ContainerMethodKind, int> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            int headerLength = ContainerMethodHarness.HeaderLengthOf(kind);
            foreach (int length in new[] { 0, 1, 2, 3, 4, 5, 6, headerLength - 1, headerLength, headerLength + 1 })
            {
                data.Add(kind, length);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(BoundaryTruncations))]
    public async Task NoMalformedContainerEverThrowsAnInternalFailure(ContainerMethodKind kind, int truncateTo)
    {
        byte[] container = await ContainerAsync(kind);

        Exception? exception = await Record.ExceptionAsync(
            () => ContainerMethodHarness.For(kind).DecryptToBytesAsync(container[..truncateTo]));

        Assert.NotNull(exception);
        Assert.IsNotType<NullReferenceException>(exception);
        Assert.IsNotType<IndexOutOfRangeException>(exception);
        Assert.IsNotType<ArgumentOutOfRangeException>(exception);
        Assert.IsNotType<ArgumentException>(exception);
        Assert.IsNotType<OutOfMemoryException>(exception);
        Assert.IsNotType<IOException>(exception);
        Assert.IsNotType<InvalidOperationException>(exception);
        Assert.IsNotType<CryptographicException>(exception);
        Assert.IsAssignableFrom<DataEncryptionException>(exception);
    }

    // --- The shared assertion ----------------------------------------------------------------------

    /// <summary>
    /// Decrypts a malformed container and asserts the outcome is one of the two container exception types.
    /// </summary>
    /// <param name="kind">The service to drive.</param>
    /// <param name="container">The malformed bytes.</param>
    /// <returns>A task representing the assertion.</returns>
    private static async Task AssertContainerErrorAsync(ContainerMethodKind kind, byte[] container)
    {
        Exception? exception = await Record.ExceptionAsync(
            () => ContainerMethodHarness.For(kind).DecryptToBytesAsync(container));

        Assert.NotNull(exception);
        Assert.True(
            exception is DataEncryptionFormatException or DataDecryptionException,
            $"{kind}: expected DataEncryptionFormatException or DataDecryptionException, "
            + $"got {exception.GetType().FullName}: {exception.Message}");
    }

    /// <summary>
    /// The one good container per method, written once and shared by every case in this class.
    /// </summary>
    /// <param name="kind">The method.</param>
    /// <returns>The container bytes.</returns>
    private static Task<byte[]> ContainerAsync(ContainerMethodKind kind) =>
        Containers.GetOrAdd(
            kind,
            static k => ContainerMethodHarness.For(k)
                .EncryptToBytesAsync(ContainerFixtures.Plaintext(PayloadLength)));
}
