using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The ML-KEM (method <c>0x04</c>) header offsets, the encapsulation length each parameter set produces, and
/// the two-line helpers that turn a container into bytes and back.
/// </summary>
/// <remarks>
/// The offsets are written out rather than computed so that a layout change in <see cref="FormatLayout"/>
/// shows up here as a failing test instead of quietly moving the tests along with it —
/// <c>docs/format.md</c> §3.4 is the source they were transcribed from. Note that the parameter-set byte
/// sits <b>before</b> the nonce, which is what makes every offset from 5 onward differ from RSA's.
/// </remarks>
// ReSharper disable once InconsistentNaming
internal static class MLKemTestData
{
    /// <summary>Header offset of the parameter-set byte.</summary>
    internal const int ParameterSetOffset = 5;

    /// <summary>Header offset of the 12-byte GCM nonce.</summary>
    internal const int NonceOffset = 6;

    /// <summary>Header offset of the little-endian encapsulation length.</summary>
    internal const int EncapsulationLengthOffset = 18;

    /// <summary>Header offset of the encapsulation itself.</summary>
    internal const int EncapsulationOffset = 22;

    /// <summary>The encapsulation length ML-KEM-512 produces.</summary>
    internal const int EncapsulationLength512 = 768;

    /// <summary>The encapsulation length ML-KEM-768 produces.</summary>
    internal const int EncapsulationLength768 = 1_088;

    /// <summary>The encapsulation length ML-KEM-1024 produces.</summary>
    internal const int EncapsulationLength1024 = 1_568;

    /// <summary>All four ciphers, for the theories that sweep them.</summary>
    internal static Cipher[] AllCiphers =>
        [Cipher.Aes256Gcm, Cipher.Twofish256Gcm, Cipher.Serpent256Gcm, Cipher.Camellia256Gcm];

    /// <summary>The encapsulation length <c>N</c> a parameter set produces, per <c>docs/format.md</c> §3.4.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>768, 1,088 or 1,568.</returns>
    internal static int EncapsulationLengthOf(MLKemParameterSet parameterSet) => parameterSet switch
    {
        MLKemParameterSet.MLKem512 => EncapsulationLength512,
        MLKemParameterSet.MLKem768 => EncapsulationLength768,
        _ => EncapsulationLength1024,
    };

    /// <summary>The header byte a parameter set is written as — <c>0x01</c>, <c>0x02</c> or <c>0x03</c>.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The wire byte.</returns>
    /// <remarks>
    /// Transcribed from §3.4 rather than taken from <see cref="MLKemParameterSetWire"/>, so the tests do not
    /// verify the mapping against itself. The enum's own numeric values are 0/1/2, which is exactly the
    /// off-by-one this table exists to catch.
    /// </remarks>
    internal static byte WireByteOf(MLKemParameterSet parameterSet) => parameterSet switch
    {
        MLKemParameterSet.MLKem512 => 0x01,
        MLKemParameterSet.MLKem768 => 0x02,
        _ => 0x03,
    };

    /// <summary>The total header length of an ML-KEM container, per <c>docs/format.md</c> §3.4.</summary>
    /// <param name="encapsulationLength">The encapsulation length <c>N</c>.</param>
    /// <returns>38 + <paramref name="encapsulationLength"/>.</returns>
    internal static int HeaderLength(int encapsulationLength) =>
        FormatLayout.MLKemHeaderBaseLength + encapsulationLength;

    /// <summary>The total header length of a container for a parameter set.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>806, 1,126 or 1,606.</returns>
    internal static int HeaderLengthOf(MLKemParameterSet parameterSet) =>
        HeaderLength(EncapsulationLengthOf(parameterSet));

    /// <summary>Header offset of the key-confirmation tag, for a given encapsulation length.</summary>
    /// <param name="encapsulationLength">The encapsulation length <c>N</c>.</param>
    /// <returns>22 + <paramref name="encapsulationLength"/>.</returns>
    internal static int KeyConfirmationTagOffset(int encapsulationLength) =>
        EncapsulationOffset + encapsulationLength;

    /// <summary>Builds a service over the real Enigma.Core factories, optionally with test doubles.</summary>
    /// <param name="randomSource">The nonce source; <see langword="null"/> uses the real one.</param>
    /// <param name="mlKemServiceFactory">The ML-KEM factory; <see langword="null"/> uses the real one.</param>
    /// <returns>The service.</returns>
    internal static MLKemDataEncryptionService Service(
        IRandomSource? randomSource = null,
        IMLKemServiceFactory? mlKemServiceFactory = null) =>
        new(new BlockCipherServiceFactory(),
            mlKemServiceFactory ?? new MLKemServiceFactory(),
            new HmacServiceFactory(),
            randomSource ?? new RandomSource());

    /// <summary>
    /// A service whose nonce is the fixed golden one, so its output is reproducible except for the
    /// encapsulation and the shared secret that comes with it.
    /// </summary>
    /// <returns>The service.</returns>
    internal static MLKemDataEncryptionService Deterministic() =>
        Service(new FixedNonceSource(FormatTestData.Nonce()));

    /// <summary>Encrypts a plaintext and returns the complete container.</summary>
    /// <param name="publicKey">The recipient's raw ML-KEM public key.</param>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="parameterSet">The parameter set to encapsulate under.</param>
    /// <param name="service">The service to use; <see langword="null"/> builds a default one.</param>
    /// <returns>The container bytes.</returns>
    internal static async Task<byte[]> EncryptToBytesAsync(
        byte[] publicKey,
        byte[] plaintext,
        Cipher cipher = Cipher.Aes256Gcm,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        MLKemDataEncryptionService? service = null)
    {
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await (service ?? Service()).EncryptAsync(
            input, output, cipher, publicKey, parameterSet, null, CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>Decrypts a container and returns the recovered plaintext.</summary>
    /// <param name="privateKey">The recipient's raw ML-KEM private key.</param>
    /// <param name="container">The container bytes.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <param name="service">The service to use; <see langword="null"/> builds a default one.</param>
    /// <returns>The recovered plaintext.</returns>
    internal static async Task<byte[]> DecryptToBytesAsync(
        byte[] privateKey,
        byte[] container,
        DataEncryptionLimits? limits = null,
        MLKemDataEncryptionService? service = null)
    {
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();
        await (service ?? Service()).DecryptAsync(
            input, output, privateKey, limits, null, CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>The encapsulation bytes carried by a container.</summary>
    /// <param name="container">The container bytes.</param>
    /// <param name="encapsulationLength">The encapsulation length <c>N</c>.</param>
    /// <returns>The <c>N</c> bytes at offset 22.</returns>
    internal static byte[] EncapsulationOf(byte[] container, int encapsulationLength) =>
        container[EncapsulationOffset..(EncapsulationOffset + encapsulationLength)];

    /// <summary>The little-endian encoding of a 32-bit value, as the format writes it.</summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The four bytes.</returns>
    internal static byte[] LittleEndian(int value) =>
        [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];

    /// <summary>Recovers a shared secret with Enigma.Core's ML-KEM directly, bypassing this library.</summary>
    /// <param name="encapsulation">The encapsulation.</param>
    /// <param name="privateKey">The recipient's private key.</param>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The 32-byte shared secret.</returns>
    internal static byte[] Decapsulate(
        byte[] encapsulation,
        byte[] privateKey,
        MLKemParameterSet parameterSet) =>
        new MLKemServiceFactory().CreateMLKemService(parameterSet).Decapsulate(encapsulation, privateKey);

    /// <summary>Encapsulates against a public key with Enigma.Core's ML-KEM directly.</summary>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The encapsulation and the shared secret.</returns>
    internal static (byte[] Encapsulation, byte[] SharedSecret) Encapsulate(
        byte[] publicKey,
        MLKemParameterSet parameterSet) =>
        new MLKemServiceFactory().CreateMLKemService(parameterSet).Encapsulate(publicKey);

    /// <summary>
    /// Builds a method-<c>0x04</c> header directly through <see cref="HeaderWriter"/>, for the cases a
    /// hostile <i>sender</i> could produce but the service itself never writes.
    /// </summary>
    /// <param name="parameterSet">The parameter set to record at offset 5.</param>
    /// <param name="encapsulation">The encapsulation bytes to embed.</param>
    /// <param name="dataKey">The key the confirmation tag is computed under.</param>
    /// <param name="cipher">The cipher byte to record.</param>
    /// <returns>The complete header bytes.</returns>
    internal static async Task<byte[]> BuildHeaderAsync(
        MLKemParameterSet parameterSet,
        byte[] encapsulation,
        byte[] dataKey,
        Cipher cipher = Cipher.Aes256Gcm)
    {
        using MemoryStream output = new();
        return await HeaderWriter.WriteMLKemHeaderAsync(
            output,
            cipher,
            parameterSet,
            FormatTestData.Nonce(),
            encapsulation,
            dataKey,
            FormatTestData.HmacSha256(),
            CancellationToken.None);
    }

    /// <summary>A deterministic plaintext of the requested length.</summary>
    /// <param name="length">How many bytes.</param>
    /// <returns>The plaintext bytes.</returns>
    internal static byte[] Plaintext(int length = 512) => ContainerFixtures.Plaintext(length);

    /// <summary>Reads a committed fixture file.</summary>
    /// <param name="fileName">The file's name within <c>Services/Fixtures</c>.</param>
    /// <returns>The file's bytes.</returns>
    internal static byte[] Fixture(string fileName) => ContainerFixtures.Read(fileName);

    /// <summary>The committed golden plaintext — the same 45 bytes the other methods' vectors use.</summary>
    /// <returns>The plaintext bytes.</returns>
    internal static byte[] GoldenPlaintext() => ContainerFixtures.Read("golden-plaintext.txt");

    /// <summary>The committed golden public key for a parameter set.</summary>
    /// <param name="slug">The fixture slug — <c>512</c> or <c>1024</c>.</param>
    /// <returns>The raw FIPS 203 public key.</returns>
    internal static byte[] GoldenPublicKey(string slug) => ContainerFixtures.Read($"mlkem-{slug}-public.key");

    /// <summary>The committed golden private key for a parameter set.</summary>
    /// <param name="slug">The fixture slug — <c>512</c> or <c>1024</c>.</param>
    /// <returns>The raw expanded FIPS 203 private key.</returns>
    internal static byte[] GoldenPrivateKey(string slug) => ContainerFixtures.Read($"mlkem-{slug}-private.key");

    /// <summary>
    /// The committed shared secret the golden encapsulation yields — the ML-KEM analogue of the password
    /// methods' fixed data key, except that the KEM chose it rather than the specification.
    /// </summary>
    /// <param name="slug">The fixture slug — <c>512</c> or <c>1024</c>.</param>
    /// <returns>The 32-byte shared secret.</returns>
    internal static byte[] GoldenSecret(string slug) => ContainerFixtures.Read($"mlkem-{slug}-secret.bin");
}
