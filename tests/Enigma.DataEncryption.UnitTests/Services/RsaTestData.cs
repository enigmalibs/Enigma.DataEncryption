using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The RSA (method <c>0x03</c>) header offsets, the fixed golden inputs, and the two-line helpers that turn
/// a container into bytes and back.
/// </summary>
/// <remarks>
/// The offsets are written out rather than computed so that a layout change in
/// <see cref="FormatLayout"/> shows up here as a failing test instead of quietly moving the tests along
/// with it — <c>docs/format.md</c> §3.3 is the source they were transcribed from.
/// </remarks>
internal static class RsaTestData
{
    /// <summary>Header offset of the OAEP-hash byte.</summary>
    internal const int OaepHashOffset = 5;

    /// <summary>Header offset of the 12-byte GCM nonce.</summary>
    internal const int NonceOffset = 6;

    /// <summary>Header offset of the little-endian wrapped-key length.</summary>
    internal const int WrappedKeyLengthOffset = 18;

    /// <summary>Header offset of the wrapped key itself.</summary>
    internal const int WrappedKeyOffset = 22;

    /// <summary>The wrapped-key length an RSA-2048 key produces — the modulus size in bytes.</summary>
    internal const int WrappedKeyLength2048 = 256;

    /// <summary>The total header length for an RSA-2048 container: 38 + 256.</summary>
    internal const int HeaderLength2048 = FormatLayout.RsaHeaderBaseLength + WrappedKeyLength2048;

    /// <summary>The passphrase protecting the committed encrypted private-key PEM.</summary>
    internal const string GoldenPemPassphrase = "enigma-test-pem-passphrase";

    /// <summary>The three OAEP hashes the format accepts, for the theories that sweep them.</summary>
    internal static RsaOaepHash[] AllOaepHashes =>
        [RsaOaepHash.Sha256, RsaOaepHash.Sha384, RsaOaepHash.Sha512];

    /// <summary>The total header length of an RSA container, per <c>docs/format.md</c> §3.3.</summary>
    /// <param name="wrappedKeyLength">The wrapped-key length <c>N</c>.</param>
    /// <returns>38 + <paramref name="wrappedKeyLength"/>.</returns>
    internal static int HeaderLength(int wrappedKeyLength) =>
        FormatLayout.RsaHeaderBaseLength + wrappedKeyLength;

    /// <summary>Header offset of the key-confirmation tag, for a given wrapped-key length.</summary>
    /// <param name="wrappedKeyLength">The wrapped-key length <c>N</c>.</param>
    /// <returns>22 + <paramref name="wrappedKeyLength"/>.</returns>
    internal static int KeyConfirmationTagOffset(int wrappedKeyLength) =>
        WrappedKeyOffset + wrappedKeyLength;

    /// <summary>Builds a service over the real Enigma.Core factories, optionally with test doubles.</summary>
    /// <param name="randomSource">The data-key/nonce source; <see langword="null"/> uses the real one.</param>
    /// <param name="publicKeyServiceFactory">The RSA factory; <see langword="null"/> uses the real one.</param>
    /// <returns>The service.</returns>
    internal static RsaDataEncryptionService Service(
        IRandomSource? randomSource = null,
        IPublicKeyServiceFactory? publicKeyServiceFactory = null) =>
        new(new BlockCipherServiceFactory(),
            publicKeyServiceFactory ?? new PublicKeyServiceFactory(),
            new HmacServiceFactory(),
            randomSource ?? new RandomSource());

    /// <summary>
    /// A service whose data key and nonce are the fixed golden ones, so its output is reproducible except
    /// for the OAEP-randomized wrapped key.
    /// </summary>
    /// <returns>The service.</returns>
    internal static RsaDataEncryptionService Deterministic() =>
        Service(new FixedDataKeyAndNonceSource(FormatTestData.DataKey(), FormatTestData.Nonce()));

    /// <summary>Encrypts a plaintext and returns the complete container.</summary>
    /// <param name="publicKeyPem">The recipient's public key.</param>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="service">The service to use; <see langword="null"/> builds a default one.</param>
    /// <returns>The container bytes.</returns>
    internal static async Task<byte[]> EncryptToBytesAsync(
        string publicKeyPem,
        byte[] plaintext,
        Cipher cipher = Cipher.Aes256Gcm,
        RsaDataEncryptionService? service = null,
        RsaOaepHash oaepHash = RsaOaepHash.Sha256)
    {
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await (service ?? Service()).EncryptAsync(
            input, output, cipher, publicKeyPem, oaepHash, null, CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>Decrypts a container and returns the recovered plaintext.</summary>
    /// <param name="privateKeyPem">The recipient's private key.</param>
    /// <param name="container">The container bytes.</param>
    /// <param name="keyPassword">The passphrase protecting <paramref name="privateKeyPem"/>, if any.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <param name="service">The service to use; <see langword="null"/> builds a default one.</param>
    /// <returns>The recovered plaintext.</returns>
    internal static async Task<byte[]> DecryptToBytesAsync(
        string privateKeyPem,
        byte[] container,
        char[]? keyPassword = null,
        DataEncryptionLimits? limits = null,
        RsaDataEncryptionService? service = null)
    {
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();
        await (service ?? Service()).DecryptAsync(
            input, output, privateKeyPem, keyPassword, limits, null, CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>The wrapped-key bytes carried by a container.</summary>
    /// <param name="container">The container bytes.</param>
    /// <param name="wrappedKeyLength">The wrapped-key length <c>N</c>.</param>
    /// <returns>The <c>N</c> bytes at offset 22.</returns>
    internal static byte[] WrappedKeyOf(byte[] container, int wrappedKeyLength = WrappedKeyLength2048) =>
        container[WrappedKeyOffset..(WrappedKeyOffset + wrappedKeyLength)];

    /// <summary>The little-endian encoding of a 32-bit value, as the format writes it.</summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The four bytes.</returns>
    internal static byte[] LittleEndian(int value) =>
        [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];

    /// <summary>The committed golden plaintext — the same 45 bytes the password vectors use.</summary>
    /// <returns>The plaintext bytes.</returns>
    internal static byte[] GoldenPlaintext() => ContainerFixtures.Read("golden-plaintext.txt");

    /// <summary>The committed RSA-2048 public key of the golden vectors.</summary>
    /// <returns>The PEM text.</returns>
    internal static string GoldenPublicKeyPem() => ContainerFixtures.ReadText("rsa-2048-public.pem");

    /// <summary>The committed RSA-2048 private key of the golden vectors, unencrypted.</summary>
    /// <returns>The PEM text.</returns>
    internal static string GoldenPrivateKeyPem() => ContainerFixtures.ReadText("rsa-2048-private.pem");

    /// <summary>
    /// The same committed private key in a PKCS#8 encrypted PEM, protected by
    /// <see cref="GoldenPemPassphrase"/>.
    /// </summary>
    /// <returns>The PEM text.</returns>
    internal static string GoldenEncryptedPrivateKeyPem() =>
        ContainerFixtures.ReadText("rsa-2048-private-encrypted.pem");

    /// <summary>A fresh copy of <see cref="GoldenPemPassphrase"/> as characters.</summary>
    /// <returns>The passphrase characters.</returns>
    internal static char[] GoldenPemPassphraseChars() => GoldenPemPassphrase.ToCharArray();

    /// <summary>
    /// Builds a method-<c>0x03</c> header directly through <see cref="HeaderWriter"/>, for the cases a
    /// hostile <i>sender</i> could produce but the service itself never writes.
    /// </summary>
    /// <param name="wrappedKey">The wrapped-key bytes to embed.</param>
    /// <param name="dataKey">The key the confirmation tag is computed under.</param>
    /// <param name="cipher">The cipher byte to record.</param>
    /// <param name="oaepHash">The OAEP hash to record at offset 5.</param>
    /// <returns>The complete header bytes.</returns>
    internal static async Task<byte[]> BuildHeaderAsync(
        byte[] wrappedKey,
        byte[] dataKey,
        Cipher cipher = Cipher.Aes256Gcm,
        RsaOaepHash oaepHash = RsaOaepHash.Sha256)
    {
        using MemoryStream output = new();
        return await HeaderWriter.WriteRsaHeaderAsync(
            output,
            cipher,
            oaepHash,
            FormatTestData.Nonce(),
            wrappedKey,
            dataKey,
            FormatTestData.HmacSha256(),
            CancellationToken.None);
    }

    /// <summary>Wraps arbitrary bytes under a public key with the same OAEP parameters the format uses.</summary>
    /// <param name="data">The bytes to wrap.</param>
    /// <param name="publicKeyPem">The recipient's public key.</param>
    /// <param name="oaepHash">The OAEP padding hash.</param>
    /// <returns>The OAEP ciphertext.</returns>
    internal static byte[] WrapOaep(
        byte[] data,
        string publicKeyPem,
        RsaOaepHash oaepHash = RsaOaepHash.Sha256) =>
        new PublicKeyServiceFactory().CreatePublicKeyService()
            .EncryptOaep(data, publicKeyPem, oaepHash);

    /// <summary>Unwraps with the same OAEP parameters the format uses.</summary>
    /// <param name="wrappedKey">The OAEP ciphertext.</param>
    /// <param name="privateKeyPem">The recipient's private key.</param>
    /// <param name="keyPassword">The passphrase protecting the PEM, if any.</param>
    /// <param name="oaepHash">The OAEP padding hash.</param>
    /// <returns>The recovered bytes.</returns>
    internal static byte[] UnwrapOaep(
        byte[] wrappedKey,
        string privateKeyPem,
        char[]? keyPassword = null,
        RsaOaepHash oaepHash = RsaOaepHash.Sha256) =>
        new PublicKeyServiceFactory().CreatePublicKeyService()
            .DecryptOaep(wrappedKey, privateKeyPem, oaepHash, keyPassword);

    /// <summary>All four ciphers, for the theories that sweep them.</summary>
    internal static Cipher[] AllCiphers =>
        [Cipher.Aes256Gcm, Cipher.Twofish256Gcm, Cipher.Serpent256Gcm, Cipher.Camellia256Gcm];

    /// <summary>A deterministic plaintext of the requested length.</summary>
    /// <param name="length">How many bytes.</param>
    /// <returns>The plaintext bytes.</returns>
    internal static byte[] Plaintext(int length = 512) => ContainerFixtures.Plaintext(length);

    /// <summary>Reads a committed fixture file.</summary>
    /// <param name="fileName">The file's name within <c>Services/Fixtures</c>.</param>
    /// <returns>The file's bytes.</returns>
    internal static byte[] Fixture(string fileName) => ContainerFixtures.Read(fileName);

    /// <summary>A PEM string that is structurally malformed — its Base64 body is not Base64.</summary>
    internal const string MalformedPem =
        "-----BEGIN PRIVATE KEY-----\nthis is not base64 at all!!!\n-----END PRIVATE KEY-----\n";

    /// <summary>Text that is not a PEM at all.</summary>
    internal const string NotAPem = "definitely not a PEM";

    /// <summary>
    /// Walks an exception's <see cref="Exception.InnerException"/> chain looking for the
    /// <see cref="FormatException"/> the Base64 decoder raises.
    /// </summary>
    /// <param name="exception">The exception Enigma.Core surfaced.</param>
    /// <returns>The nested <see cref="FormatException"/>, or <see langword="null"/> if the chain holds none.</returns>
    /// <remarks>
    /// The depth is walked rather than indexed because it is BouncyCastle's, not ours: 2.7.0 nests the
    /// decoder's failure inside an <see cref="IOException"/> before Enigma.Core maps that to an
    /// <see cref="ArgumentException"/>, and a future version could add or drop a layer without changing the
    /// outcome the format spec cares about.
    /// </remarks>
    internal static FormatException? FirstFormatException(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is FormatException format)
            {
                return format;
            }
        }

        return null;
    }
}
