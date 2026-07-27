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
/// Golden vectors for method <c>0x02</c>, in both directions: the exact bytes the service must write for
/// fixed inputs, and committed container files it must read back to an exact plaintext.
/// </summary>
/// <remarks>
/// <para>
/// <b>The data key is pinned by an external implementation, not by this library.</b> .NET has no Argon2,
/// so the expected key below was produced with OpenSSL 3.6:
/// </para>
/// <code>
/// openssl kdf -keylen 32 -kdfopt pass:"correct horse battery staple" \
///     -kdfopt hexsalt:101112131415161718191A1B1C1D1E1F \
///     -kdfopt iter:2 -kdfopt memcost:1024 -kdfopt lanes:1 -kdfopt threads:1 ARGON2ID
/// </code>
/// <para>
/// Everything built on that key — the key-confirmation tag and the AES-256-GCM payload — is then rebuilt
/// at run time from the platform's own primitives in
/// <see cref="TheGoldenAesContainerIsWhatTheIndependentPrimitivesProduce"/>. Since both the tag and the
/// payload depend on the key, a container that matches proves the service derived exactly the key OpenSSL
/// did: Argon2id, version 1.3, 32 bytes, with the header's three cost values.
/// </para>
/// <para>
/// The Twofish vector is a regression vector — see the note in <c>Pbkdf2GoldenVectorTests</c> — its
/// payload having been produced by Enigma.Core's own primitive.
/// </para>
/// <para>Inputs: the same password, salt, nonce and plaintext as the PBKDF2 vectors, at 2 passes over
/// 1,024 KiB with a single lane. The three cost values are pairwise different, so a transposed field
/// order cannot pass.</para>
/// </remarks>
public sealed class Argon2GoldenVectorTests
{
    private const int Iterations = 2;
    private const int MemorySizeKb = 1_024;
    private const int DegreeOfParallelism = 1;

    /// <summary>
    /// The complete 122-byte AES-256-GCM container: 61-byte header, 45-byte ciphertext, 16-byte GCM tag.
    /// </summary>
    private static readonly byte[] ExpectedAesContainer =
    [
        0xEC, 0xDE,                                     // magic
        0x02,                                           // method: Argon2
        0x10,                                           // format version
        0x01,                                           // cipher: AES-256-GCM
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,                         // nonce
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // salt
        0x02, 0x00, 0x00, 0x00,                         // iterations: 2
        0x01, 0x00, 0x00, 0x00,                         // degree of parallelism: 1  (before memory)
        0x00, 0x04, 0x00, 0x00,                         // memory: 1,024 KiB, little-endian
        0x45, 0x6E, 0x03, 0x85, 0x7C, 0x91, 0x52, 0xA2, // key-confirmation tag
        0x65, 0x9A, 0xBD, 0x18, 0xA5, 0xD7, 0x32, 0x4A,

        // payload: ciphertext
        0xF4, 0x8B, 0x15, 0x51, 0xC8, 0x32, 0x35, 0xD0, 0x13, 0xEC, 0x0E, 0x2D,
        0x98, 0x28, 0x3E, 0x49, 0x07, 0x85, 0xAC, 0x47, 0xA0, 0x9C, 0x04, 0x64,
        0x73, 0x28, 0x6F, 0x79, 0x48, 0x30, 0xCC, 0x47, 0x95, 0x16, 0x9A, 0xFD,
        0xFE, 0x45, 0xF7, 0x61, 0xF4, 0x02, 0x70, 0xCE, 0x94,

        // payload: GCM authentication tag
        0x5A, 0x88, 0x63, 0x43, 0xC1, 0x65, 0x3F, 0x59,
        0xFC, 0xFC, 0xA0, 0x90, 0xA0, 0xC4, 0x29, 0x20,
    ];

    /// <summary>The same container under Twofish-256-GCM.</summary>
    private static readonly byte[] ExpectedTwofishContainer =
    [
        0xEC, 0xDE,                                     // magic
        0x02,                                           // method: Argon2
        0x10,                                           // format version
        0x02,                                           // cipher: Twofish-256-GCM
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,                         // nonce
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, // salt
        0x02, 0x00, 0x00, 0x00,                         // iterations: 2
        0x01, 0x00, 0x00, 0x00,                         // degree of parallelism: 1
        0x00, 0x04, 0x00, 0x00,                         // memory: 1,024 KiB
        0x8E, 0x9C, 0xBC, 0xE1, 0xA3, 0x3C, 0x49, 0xB3, // key-confirmation tag
        0xEF, 0x08, 0x53, 0x55, 0x7D, 0x39, 0xAA, 0xCA,

        // payload: ciphertext
        0x35, 0xFA, 0xE6, 0xBD, 0xB3, 0xF2, 0x5A, 0xD2, 0x99, 0x91, 0x79, 0x8D,
        0x26, 0x95, 0xA3, 0x03, 0x97, 0x7E, 0x1A, 0x77, 0x3D, 0x22, 0x2C, 0xAD,
        0x6E, 0x03, 0x13, 0xE7, 0x17, 0x9B, 0xBC, 0xF4, 0xCF, 0xB5, 0x93, 0xDA,
        0x37, 0x05, 0xBF, 0x54, 0xB4, 0x5E, 0xCF, 0x9D, 0x43,

        // payload: GCM authentication tag
        0x4B, 0xFC, 0x5A, 0x25, 0xDB, 0x2D, 0xB4, 0xE1,
        0x02, 0xA7, 0x83, 0xCB, 0xB5, 0xD0, 0x84, 0x63,
    ];

    /// <summary>The Argon2id data key the vectors' inputs derive to, per the OpenSSL command above.</summary>
    private static readonly byte[] ExpectedDataKey =
    [
        0x25, 0xD7, 0x85, 0x25, 0x58, 0x11, 0xC3, 0x72, 0x0A, 0xC6, 0x16, 0x68, 0xFD, 0x72, 0x7C, 0x08,
        0x23, 0x3F, 0x4F, 0x59, 0x50, 0xC5, 0xDB, 0xE4, 0x48, 0xD7, 0x10, 0x77, 0x7A, 0xCC, 0xAF, 0xFB,
    ];

    // --- Write path ---------------------------------------------------------------------------------

    [Fact]
    public async Task TheGoldenAesContainerIsReproducedByteForByte() =>
        Assert.Equal(ExpectedAesContainer, await WriteGoldenContainerAsync(Cipher.Aes256Gcm));

    [Fact]
    public async Task TheGoldenTwofishContainerIsReproducedByteForByte() =>
        Assert.Equal(ExpectedTwofishContainer, await WriteGoldenContainerAsync(Cipher.Twofish256Gcm));

    /// <summary>
    /// The AES vector rebuilt from the OpenSSL-pinned data key plus the platform's HMAC and AES-GCM.
    /// </summary>
    [Fact]
    public void TheGoldenAesContainerIsWhatTheIndependentPrimitivesProduce()
    {
        // The 45 header bytes before the tag, laid out from docs/format.md §3.2 — note parallelism
        // precedes memory, and memory is the KiB value itself rather than an exponent.
        byte[] headerBeforeTag =
        [
            0xEC, 0xDE, 0x02, 0x10, (byte)Cipher.Aes256Gcm,
            .. FormatTestData.Nonce(),
            .. FormatTestData.Salt(),
            .. LittleEndian(Iterations),
            .. LittleEndian(DegreeOfParallelism),
            .. LittleEndian(MemorySizeKb),
        ];
        Assert.Equal(45, headerBeforeTag.Length);

        byte[] header =
        [
            .. headerBeforeTag,
            .. GoldenVectorPrimitives.KeyConfirmationTag(ExpectedDataKey, headerBeforeTag),
        ];
        byte[] container =
        [
            .. header,
            .. GoldenVectorPrimitives.AesGcmPayload(
                ExpectedDataKey, FormatTestData.Nonce(), header, GoldenPlaintext()),
        ];

        Assert.Equal(ExpectedAesContainer, container);
    }

    /// <summary>
    /// The default costs reach the header as the format specifies: 3 passes, 4 lanes and 65,536 KiB, with
    /// parallelism before memory (<c>docs/format.md</c> §3.2, §4.1).
    /// </summary>
    [Fact]
    public async Task TheDefaultCostsAreWrittenInTheSpecifiedOrder()
    {
        Argon2DataEncryptionService service = DeterministicService();

        using MemoryStream input = new(GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await service.EncryptAsync(
            input, output, Cipher.Aes256Gcm, GoldenPassword(),
            cancellationToken: TestContext.Current.CancellationToken);

        byte[] container = output.ToArray();
        Assert.Equal<byte[]>([0x03, 0x00, 0x00, 0x00], container[33..37]); // iterations: 3
        Assert.Equal<byte[]>([0x04, 0x00, 0x00, 0x00], container[37..41]); // parallelism: 4
        Assert.Equal<byte[]>([0x00, 0x00, 0x01, 0x00], container[41..45]); // memory: 65,536 KiB
    }

    /// <summary>
    /// The memory field is the KiB value, not the predecessor library's power-of-two exponent — the one
    /// deliberate divergence from `Enigma.Cryptography.DataEncryption` (<c>docs/format.md</c> §3.2).
    /// </summary>
    [Fact]
    public async Task TheMemoryFieldIsKibibytesAndNotAnExponent()
    {
        Argon2DataEncryptionService service = DeterministicService();

        using MemoryStream input = new(GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await service.EncryptAsync(
            input, output, Cipher.Aes256Gcm, GoldenPassword(), 1, 4_096, 1, null, TestContext.Current.CancellationToken);

        // 4,096 KiB is written as 4096 (00 10 00 00), not as the exponent 12 (0C 00 00 00).
        Assert.Equal<byte[]>([0x00, 0x10, 0x00, 0x00], output.ToArray()[41..45]);
    }

    // --- Read path ----------------------------------------------------------------------------------

    [Theory]
    [InlineData("argon2-aes.bin")]
    [InlineData("argon2-twofish.bin")]
    public async Task TheCommittedFixtureDecryptsToTheExpectedPlaintext(string fixture)
    {
        Argon2DataEncryptionService service = new();

        using MemoryStream input = new(PasswordTestData.Fixture(fixture), writable: false);
        using MemoryStream output = new();
        await service.DecryptAsync(
            input, output, GoldenPassword(), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(GoldenPlaintext(), output.ToArray());
    }

    [Fact]
    public void TheCommittedFixturesAreTheGoldenContainers()
    {
        Assert.Equal(ExpectedAesContainer, PasswordTestData.Fixture("argon2-aes.bin"));
        Assert.Equal(ExpectedTwofishContainer, PasswordTestData.Fixture("argon2-twofish.bin"));
    }

    [Fact]
    public async Task TheCommittedFixtureRejectsTheWrongPassword()
    {
        Argon2DataEncryptionService service = new();

        using MemoryStream input = new(PasswordTestData.Fixture("argon2-aes.bin"), writable: false);
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

    private static Argon2DataEncryptionService DeterministicService() =>
        new(new BlockCipherServiceFactory(),
            new Argon2ServiceFactory(),
            new HmacServiceFactory(),
            new FixedRandomSource(FormatTestData.Salt(), FormatTestData.Nonce()));

    private static async Task<byte[]> WriteGoldenContainerAsync(Cipher cipher)
    {
        using MemoryStream input = new(GoldenPlaintext(), writable: false);
        using MemoryStream output = new();
        await DeterministicService().EncryptAsync(
            input,
            output,
            cipher,
            GoldenPassword(),
            Iterations,
            MemorySizeKb,
            DegreeOfParallelism,
            null,
            TestContext.Current.CancellationToken);

        return output.ToArray();
    }
}
