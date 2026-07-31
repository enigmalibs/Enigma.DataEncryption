using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Golden vectors for method <c>0x01</c>, in both directions: the exact bytes the service must write for
/// fixed inputs, and committed container files it must read back to an exact plaintext.
/// </summary>
/// <remarks>
/// <para>
/// <b>The AES vector is independent of this library.</b> Its data key was computed with Python's
/// <c>hashlib.pbkdf2_hmac</c>, its key-confirmation tag with Python's <c>hmac</c>, and its payload with
/// the platform's <see cref="System.Security.Cryptography.AesGcm"/> — and
/// <see cref="TheGoldenAesContainerIsWhatTheIndependentPrimitivesProduce"/> rebuilds the whole container
/// from platform primitives at run time, so the independence is re-established on every run rather than
/// asserted in a comment.
/// </para>
/// <para>
/// <b>The Twofish vector is a regression vector, not an independent one.</b> No implementation of
/// Twofish-256-GCM is available outside BouncyCastle here, so its payload bytes were produced by
/// Enigma.Core's primitive. Its header — including the key-confirmation tag — is still independent, and
/// what the payload pins is that the cipher selection, the key and the AAD do not drift.
/// </para>
/// <para>The inputs: password <c>correct horse battery staple</c>, salt <c>10</c>–<c>1F</c>, nonce
/// <c>00</c>–<c>0B</c>, 100,000 iterations, and the 45-byte plaintext in
/// <c>Services/Fixtures/golden-plaintext.txt</c>.</para>
/// </remarks>
public sealed class Pbkdf2GoldenVectorTests
{
    /// <summary>The iteration count of the vectors — three distinct non-zero bytes, so a byte-swap shows.</summary>
    private const int Iterations = 100_000;

    /// <summary>
    /// The complete 114-byte AES-256-GCM container: 53-byte header, 45-byte ciphertext, 16-byte GCM tag.
    /// </summary>
    private static readonly byte[] ExpectedAesContainer =
    [
        0xEC, 0xDE,                                     // magic
        0x01,                                           // method: PBKDF2
        0x10,                                           // format version
        0x01,                                           // cipher: AES-256-GCM
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,                         // nonce
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // salt
        0xA0, 0x86, 0x01, 0x00,                         // iterations: 100,000, little-endian
        0x03, 0x46, 0x1D, 0x55, 0xD2, 0xE9, 0x81, 0x46, // key-confirmation tag
        0x32, 0xA2, 0xB6, 0x16, 0xFD, 0x37, 0x51, 0x73,

        // payload: ciphertext
        0xD9, 0xBB, 0xA6, 0xF8, 0xE9, 0x9D, 0x3F, 0xA8, 0x41, 0xAA, 0x4B, 0xDD,
        0x5F, 0x71, 0x79, 0xCD, 0x58, 0xA2, 0xDD, 0xCC, 0x54, 0xAB, 0x0E, 0x04,
        0x34, 0xD9, 0x25, 0x86, 0xAF, 0x95, 0xBF, 0x47, 0xB9, 0x2C, 0x49, 0xFD,
        0x20, 0xE2, 0xA6, 0xCA, 0x26, 0x60, 0x6A, 0x81, 0x21,

        // payload: GCM authentication tag
        0x88, 0x78, 0xAE, 0xFD, 0x17, 0xD5, 0x68, 0xE3,
        0xAD, 0x81, 0xB0, 0xAA, 0x9B, 0xED, 0xA3, 0x1B,
    ];

    /// <summary>The same container under Twofish-256-GCM — the cipher byte and the payload differ.</summary>
    private static readonly byte[] ExpectedTwofishContainer =
    [
        0xEC, 0xDE,                                     // magic
        0x01,                                           // method: PBKDF2
        0x10,                                           // format version
        0x02,                                           // cipher: Twofish-256-GCM
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,                         // nonce
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // salt
        0xA0, 0x86, 0x01, 0x00,                         // iterations: 100,000, little-endian
        0x05, 0xAE, 0xC7, 0xDA, 0xF5, 0x8B, 0xBB, 0xE4, // key-confirmation tag
        0xDD, 0x92, 0x6B, 0xAE, 0xD7, 0x4E, 0xDD, 0x4F,

        // payload: ciphertext
        0x44, 0x66, 0x83, 0x67, 0x99, 0xEC, 0x45, 0xDE, 0xAE, 0xD6, 0x80, 0x2D,
        0x1F, 0x2E, 0x52, 0x20, 0xCD, 0xBB, 0xD5, 0xCD, 0x90, 0x8A, 0x80, 0x2E,
        0xD6, 0xB5, 0x55, 0xB6, 0x07, 0x0A, 0x03, 0xF6, 0x5D, 0x03, 0x67, 0xC4,
        0xA6, 0x40, 0xE1, 0xA1, 0xC6, 0x39, 0xFA, 0xBA, 0xB7,

        // payload: GCM authentication tag
        0xA9, 0xD9, 0x8B, 0xBB, 0x85, 0x61, 0x19, 0x9E,
        0x92, 0x8F, 0x9B, 0x75, 0x10, 0x77, 0xFF, 0x71,
    ];

    /// <summary>
    /// The data key the vectors' inputs derive to, from Python:
    /// <c>hashlib.pbkdf2_hmac('sha256', b'correct horse battery staple', bytes(range(0x10, 0x20)), 100000, 32)</c>.
    /// </summary>
    private static readonly byte[] ExpectedDataKey =
    [
        0x27, 0xEC, 0x20, 0xAC, 0x9D, 0x4C, 0x5D, 0xC7, 0xE4, 0x1D, 0x7F, 0x5A, 0x5C, 0xD3, 0xDB, 0x8F,
        0x7E, 0x95, 0xA0, 0x6F, 0x11, 0xFA, 0x23, 0x2A, 0xA3, 0x79, 0x7F, 0xE8, 0xD8, 0x2A, 0xE2, 0x76,
    ];

    // --- Write path ---------------------------------------------------------------------------------

    [Fact]
    public async Task TheGoldenAesContainerIsReproducedByteForByte() =>
        Assert.Equal(ExpectedAesContainer, await WriteGoldenContainerAsync(Cipher.Aes256Gcm));

    [Fact]
    public async Task TheGoldenTwofishContainerIsReproducedByteForByte() =>
        Assert.Equal(ExpectedTwofishContainer, await WriteGoldenContainerAsync(Cipher.Twofish256Gcm));

    /// <summary>
    /// The AES vector rebuilt from the platform's PBKDF2, HMAC and AES-GCM — no library code involved in
    /// the expectation, so agreement means the format is right rather than self-consistent.
    /// </summary>
    [Fact]
    public void TheGoldenAesContainerIsWhatTheIndependentPrimitivesProduce()
    {
        byte[] dataKey = GoldenVectorPrimitives.Pbkdf2Key(GoldenPassword(), FormatTestData.Salt(), Iterations);
        Assert.Equal(ExpectedDataKey, dataKey);

        // The 37 header bytes before the tag, laid out from docs/format.md §3.1.
        byte[] headerBeforeTag =
        [
            0xEC, 0xDE, 0x01, 0x10, (byte)Cipher.Aes256Gcm,
            .. FormatTestData.Nonce(),
            .. FormatTestData.Salt(),
            .. LittleEndian(Iterations),
        ];
        Assert.Equal(37, headerBeforeTag.Length);

        byte[] header = [.. headerBeforeTag, .. GoldenVectorPrimitives.KeyConfirmationTag(dataKey, headerBeforeTag)];
        byte[] container =
        [
            .. header,
            .. GoldenVectorPrimitives.AesGcmPayload(dataKey, FormatTestData.Nonce(), header, GoldenPlaintext()),
        ];

        Assert.Equal(ExpectedAesContainer, container);
    }

    /// <summary>
    /// The default iteration count reaches the header as the format specifies: 600,000 as
    /// <c>C0 27 09 00</c> (<c>docs/format.md</c> §1.1, §4.1).
    /// </summary>
    [Fact]
    public async Task TheDefaultIterationCountIsWrittenLittleEndian()
    {
        Pbkdf2DataEncryptionService service = DeterministicService();

        using MemoryStream input = new(GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await service.EncryptAsync(
            input, output, Cipher.Aes256Gcm, GoldenPassword(),
            cancellationToken: TestContext.Current.CancellationToken);

        byte[] container = output.ToArray();
        Assert.Equal<byte[]>([0xC0, 0x27, 0x09, 0x00], container[33..37]);
        Assert.Equal(DataEncryptionDefaults.Pbkdf2Iterations, 600_000);
    }

    // --- Read path ----------------------------------------------------------------------------------

    [Theory]
    [InlineData("pbkdf2-aes.bin")]
    [InlineData("pbkdf2-twofish.bin")]
    public async Task TheCommittedFixtureDecryptsToTheExpectedPlaintext(string fixture)
    {
        Pbkdf2DataEncryptionService service = new();

        using MemoryStream input = new(PasswordTestData.Fixture(fixture), writable: false);
        using MemoryStream output = new();
        await service.DecryptAsync(
            input, output, GoldenPassword(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(GoldenPlaintext(), output.ToArray());
    }

    /// <summary>The committed files are the vectors above, so the two directions test the same bytes.</summary>
    [Fact]
    public void TheCommittedFixturesAreTheGoldenContainers()
    {
        Assert.Equal(ExpectedAesContainer, PasswordTestData.Fixture("pbkdf2-aes.bin"));
        Assert.Equal(ExpectedTwofishContainer, PasswordTestData.Fixture("pbkdf2-twofish.bin"));
    }

    /// <summary>A fixture opened with the wrong password fails, as it would in the field.</summary>
    [Fact]
    public async Task TheCommittedFixtureRejectsTheWrongPassword()
    {
        Pbkdf2DataEncryptionService service = new();

        using MemoryStream input = new(PasswordTestData.Fixture("pbkdf2-aes.bin"), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => service.DecryptAsync(
                input, output, PasswordTestData.WrongPasswordBytes(),
                cancellationToken: TestContext.Current.CancellationToken));
    }

    private static byte[] LittleEndian(int value) =>
        [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];

    private static byte[] GoldenPassword() => Encoding.UTF8.GetBytes(PasswordTestData.Password);

    private static byte[] GoldenPlaintext() => PasswordTestData.Fixture("golden-plaintext.txt");

    private static Pbkdf2DataEncryptionService DeterministicService() =>
        new(new BlockCipherServiceFactory(),
            new Pbkdf2ServiceFactory(),
            new HmacServiceFactory(),
            new FixedRandomSource(FormatTestData.Salt(), FormatTestData.Nonce()));

    private static async Task<byte[]> WriteGoldenContainerAsync(Cipher cipher)
    {
        using MemoryStream input = new(GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await DeterministicService().EncryptAsync(
            input, output, cipher, GoldenPassword(), Iterations, null, TestContext.Current.CancellationToken);

        return output.ToArray();
    }
}
