using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Asserts the bytes <see cref="HeaderWriter"/> emits against hand-written expected arrays transcribed
/// from <c>docs/format.md</c> §3.
/// </summary>
/// <remarks>
/// <para>
/// <b>Round-tripping through <see cref="HeaderReader"/> would pass with either endianness</b>, and with
/// any self-consistent field order — which is exactly what these vectors exist to rule out. Enigma.Core
/// writes <c>Int32</c> little-endian (§1.1), so 600,000 must appear as <c>C0 27 09 00</c> and not as
/// <c>00 09 27 C0</c>; the expected arrays below say so explicitly.
/// </para>
/// <para>The key-confirmation tags in these vectors were computed independently — see <c>KeyConfirmationTests</c>.</para>
/// </remarks>
public sealed class HeaderGoldenBytesTests
{
    /// <summary>
    /// The complete 53-byte PBKDF2 header for the fixed inputs, AES-256-GCM and 600,000 iterations.
    /// </summary>
    private static readonly byte[] ExpectedPbkdf2Header =
    [
        0xEC, 0xDE,                                     // magic
        0x01,                                           // method: PBKDF2
        0x10,                                           // format version
        0x01,                                           // cipher: AES-256-GCM
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,             // nonce
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // salt
        0xC0, 0x27, 0x09, 0x00,                         // iterations: 600,000, little-endian
        0xA5, 0x80, 0xEB, 0xC0, 0x66, 0x43, 0x3D, 0x13, // key-confirmation tag
        0xF6, 0x42, 0x29, 0x24, 0x5C, 0x69, 0xC4, 0xE3,
    ];

    /// <summary>
    /// The complete 61-byte Argon2 header for the fixed inputs, Twofish-256-GCM and the default costs
    /// (3 passes, 4 lanes, 65,536 KiB).
    /// </summary>
    private static readonly byte[] ExpectedArgon2Header =
    [
        0xEC, 0xDE,                                     // magic
        0x02,                                           // method: Argon2
        0x10,                                           // format version
        0x02,                                           // cipher: Twofish-256-GCM
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,             // nonce
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // salt
        0x03, 0x00, 0x00, 0x00,                         // iterations: 3
        0x04, 0x00, 0x00, 0x00,                         // degree of parallelism: 4  (before memory)
        0x00, 0x00, 0x01, 0x00,                         // memory: 65,536 KiB, little-endian
        0x98, 0x2E, 0xEF, 0xE5, 0x5C, 0x27, 0x1D, 0x7F, // key-confirmation tag
        0x7B, 0xB3, 0x49, 0x6D, 0x6C, 0x9C, 0x47, 0x52,
    ];

    [Fact]
    public async Task Pbkdf2Header_MatchesTheGoldenBytes() =>
        Assert.Equal(
            ExpectedPbkdf2Header,
            await FormatTestData.BuildHeaderAsync(HeaderShape.Pbkdf2, Cipher.Aes256Gcm));

    [Fact]
    public async Task Argon2Header_MatchesTheGoldenBytes() =>
        Assert.Equal(
            ExpectedArgon2Header,
            await FormatTestData.BuildHeaderAsync(HeaderShape.Argon2, Cipher.Twofish256Gcm));

    // --- Little-endian Int32 encoding (§1.1) ------------------------------------------------------

    /// <summary>
    /// A value whose four bytes are all distinct, so a byte-swap cannot hide: <c>0x01020304</c> must be
    /// written <c>04 03 02 01</c>.
    /// </summary>
    [Fact]
    public async Task Int32Fields_AreLittleEndian()
    {
        using MemoryStream output = new();
        byte[] header = await HeaderWriter.WritePbkdf2HeaderAsync(
            output,
            Cipher.Aes256Gcm,
            FormatTestData.Nonce(),
            FormatTestData.Salt(),
            0x01020304,
            FormatTestData.DataKey(),
            FormatTestData.HmacSha256(),
            CancellationToken.None);

        Assert.Equal<byte[]>([0x04, 0x03, 0x02, 0x01], header[33..37]);
    }

    /// <summary>
    /// The RSA wrapped-key length field, at offset 17: 256 is <c>00 01 00 00</c> little-endian, and
    /// would be <c>00 00 01 00</c> big-endian.
    /// </summary>
    [Fact]
    public async Task RsaWrappedKeyLengthField_IsLittleEndianAtOffset17()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);

        Assert.Equal<byte[]>([0x00, 0x01, 0x00, 0x00], header[17..21]);
    }

    /// <summary>The ML-KEM encapsulation length field, at offset 18: 768 is <c>00 03 00 00</c>.</summary>
    [Fact]
    public async Task MLKemEncapsulationLengthField_IsLittleEndianAtOffset18()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem);

        Assert.Equal<byte[]>([0x00, 0x03, 0x00, 0x00], header[18..22]);
    }

    // --- Common prefix and method-specific first bytes --------------------------------------------

    [Theory]
    [InlineData(HeaderShape.Pbkdf2, 0x01)]
    [InlineData(HeaderShape.Argon2, 0x02)]
    [InlineData(HeaderShape.Rsa, 0x03)]
    [InlineData(HeaderShape.MLKem, 0x04)]
    public async Task EveryShape_StartsWithTheSpecifiedCommonPrefix(HeaderShape shape, byte methodByte)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape, Cipher.Serpent256Gcm);

        Assert.Equal(0xEC, header[0]);
        Assert.Equal(0xDE, header[1]);
        Assert.Equal(methodByte, header[2]);
        Assert.Equal(0x10, header[3]);
        Assert.Equal(0x03, header[4]); // Serpent-256-GCM
    }

    /// <summary>
    /// For ML-KEM the parameter-set byte sits at offset 5, <b>before</b> the nonce — the one shape whose
    /// body does not begin with the nonce.
    /// </summary>
    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, 0x01)]
    [InlineData(MLKemParameterSet.MLKem768, 0x02)]
    [InlineData(MLKemParameterSet.MLKem1024, 0x03)]
    public async Task MLKemParameterSetByte_IsAtOffset5(MLKemParameterSet parameterSet, byte expected)
    {
        using MemoryStream output = new();
        byte[] header = await HeaderWriter.WriteMLKemHeaderAsync(
            output,
            Cipher.Aes256Gcm,
            parameterSet,
            FormatTestData.Nonce(),
            FormatTestData.Encapsulation(),
            FormatTestData.DataKey(),
            FormatTestData.HmacSha256(),
            CancellationToken.None);

        Assert.Equal(expected, header[5]);
        // …and the nonce follows it, rather than preceding it.
        Assert.Equal(FormatTestData.Nonce(), header[6..18]);
    }

    /// <summary>The variable-length field must be the bytes handed to the writer, at the specified offset.</summary>
    [Fact]
    public async Task RsaWrappedKey_IsAtOffset21()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.Rsa);

        Assert.Equal(FormatTestData.WrappedKey(), header[21..(21 + FormatTestData.RsaWrappedKeyLength)]);
    }

    /// <summary>Likewise for ML-KEM, where the encapsulation starts at offset 22.</summary>
    [Fact]
    public async Task MLKemEncapsulation_IsAtOffset22()
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(HeaderShape.MLKem);

        Assert.Equal(
            FormatTestData.Encapsulation(),
            header[22..(22 + FormatTestData.MLKemEncapsulationLength)]);
    }

    /// <summary>
    /// The tag closes every header, so the last 16 bytes are the tag over everything before them.
    /// </summary>
    [Theory]
    [InlineData(HeaderShape.Pbkdf2)]
    [InlineData(HeaderShape.Argon2)]
    [InlineData(HeaderShape.Rsa)]
    [InlineData(HeaderShape.MLKem)]
    public async Task TheLast16Bytes_AreTheKeyConfirmationTagOverEverythingBefore(HeaderShape shape)
    {
        byte[] header = await FormatTestData.BuildHeaderAsync(shape);
        int tagOffset = header.Length - DataEncryptionDefaults.KeyConfirmationTagSizeBytes;

        byte[] expected = KeyConfirmation.ComputeTag(
            FormatTestData.HmacSha256(), FormatTestData.DataKey(), header[..tagOffset]);

        Assert.Equal(expected, header[tagOffset..]);
    }
}
