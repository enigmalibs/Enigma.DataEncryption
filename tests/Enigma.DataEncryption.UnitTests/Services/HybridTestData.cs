using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The hybrid (method <c>0x05</c>) header offsets, the fixed golden inputs, and the two-line helpers that
/// turn a container into bytes and back.
/// </summary>
/// <remarks>
/// <para>
/// The offsets are written out rather than computed so that a layout change in <see cref="FormatLayout"/>
/// shows up here as a failing test instead of quietly moving the tests along with it —
/// <c>docs/format.md</c> §3.5 is the source they were transcribed from.
/// </para>
/// <para>
/// Note which offsets are constants and which are functions of <c>N</c>. The hybrid is the only shape with
/// <b>two</b> variable-length fields, so everything from the encapsulation length onwards depends on the
/// wrapped-secret length that precedes it. Writing those as methods rather than constants is what keeps a
/// test from silently assuming an RSA-2048 modulus.
/// </para>
/// </remarks>
internal static class HybridTestData
{
    /// <summary>Header offset of the ML-KEM parameter-set byte — the same offset as method <c>0x04</c>'s.</summary>
    internal const int ParameterSetOffset = 5;

    /// <summary>Header offset of the 12-byte GCM nonce.</summary>
    internal const int NonceOffset = 6;

    /// <summary>Header offset of the little-endian wrapped-secret length.</summary>
    internal const int WrappedSecretLengthOffset = 18;

    /// <summary>Header offset of the RSAES-OAEP ciphertext itself.</summary>
    internal const int WrappedSecretOffset = 22;

    /// <summary>The wrapped-secret length an RSA-2048 key produces — the modulus size in bytes.</summary>
    internal const int WrappedSecretLength2048 = 256;

    /// <summary>The passphrase protecting the committed encrypted private-key PEM.</summary>
    internal const string GoldenPemPassphrase = RsaTestData.GoldenPemPassphrase;

    /// <summary>All four ciphers, for the theories that sweep them.</summary>
    internal static Cipher[] AllCiphers =>
        [Cipher.Aes256Gcm, Cipher.Twofish256Gcm, Cipher.Serpent256Gcm, Cipher.Camellia256Gcm];

    /// <summary>Header offset of the little-endian encapsulation length.</summary>
    /// <param name="wrappedSecretLength">The wrapped-secret length <c>N</c>.</param>
    /// <returns>22 + <paramref name="wrappedSecretLength"/>.</returns>
    internal static int EncapsulationLengthOffset(int wrappedSecretLength) =>
        WrappedSecretOffset + wrappedSecretLength;

    /// <summary>Header offset of the ML-KEM encapsulation itself.</summary>
    /// <param name="wrappedSecretLength">The wrapped-secret length <c>N</c>.</param>
    /// <returns>26 + <paramref name="wrappedSecretLength"/>.</returns>
    internal static int EncapsulationOffset(int wrappedSecretLength) =>
        EncapsulationLengthOffset(wrappedSecretLength) + 4;

    /// <summary>Header offset of the key-confirmation tag.</summary>
    /// <param name="wrappedSecretLength">The wrapped-secret length <c>N</c>.</param>
    /// <param name="encapsulationLength">The encapsulation length <c>M</c>.</param>
    /// <returns>26 + <paramref name="wrappedSecretLength"/> + <paramref name="encapsulationLength"/>.</returns>
    internal static int KeyConfirmationTagOffset(int wrappedSecretLength, int encapsulationLength) =>
        EncapsulationOffset(wrappedSecretLength) + encapsulationLength;

    /// <summary>The total header length of a hybrid container, per <c>docs/format.md</c> §3.5.</summary>
    /// <param name="wrappedSecretLength">The wrapped-secret length <c>N</c>.</param>
    /// <param name="encapsulationLength">The encapsulation length <c>M</c>.</param>
    /// <returns>42 + <paramref name="wrappedSecretLength"/> + <paramref name="encapsulationLength"/>.</returns>
    internal static int HeaderLength(int wrappedSecretLength, int encapsulationLength) =>
        FormatLayout.HybridHeaderBaseLength + wrappedSecretLength + encapsulationLength;

    /// <summary>
    /// The total header length for an RSA-2048 container at a given ML-KEM parameter set — the shape every
    /// suite here uses.
    /// </summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>1,066, 1,386 or 1,866.</returns>
    internal static int HeaderLengthOf(MLKemParameterSet parameterSet) =>
        HeaderLength(WrappedSecretLength2048, MLKemTestData.EncapsulationLengthOf(parameterSet));

    /// <summary>Builds a service over the real Enigma.Core factories, optionally with test doubles.</summary>
    /// <param name="randomSource">The nonce/RSA-secret source; <see langword="null"/> uses the real one.</param>
    /// <param name="publicKeyServiceFactory">The RSA factory; <see langword="null"/> uses the real one.</param>
    /// <param name="mlKemServiceFactory">The ML-KEM factory; <see langword="null"/> uses the real one.</param>
    /// <param name="hmacServiceFactory">The HMAC factory; <see langword="null"/> uses the real one.</param>
    /// <returns>The service.</returns>
    internal static HybridDataEncryptionService Service(
        IRandomSource? randomSource = null,
        IPublicKeyServiceFactory? publicKeyServiceFactory = null,
        IMLKemServiceFactory? mlKemServiceFactory = null,
        IHmacServiceFactory? hmacServiceFactory = null) =>
        new(new BlockCipherServiceFactory(),
            publicKeyServiceFactory ?? new PublicKeyServiceFactory(),
            mlKemServiceFactory ?? new MLKemServiceFactory(),
            hmacServiceFactory ?? new HmacServiceFactory(),
            randomSource ?? new RandomSource());

    /// <summary>
    /// A service whose nonce and RSA-half secret are the fixed golden ones, so its output is reproducible
    /// except for the OAEP-randomized ciphertext and the freshly encapsulated ML-KEM pair.
    /// </summary>
    /// <returns>The service.</returns>
    /// <remarks>
    /// Two independent sources of randomness remain, which is one more than either public-key method has
    /// on its own — see <c>HybridGoldenVectorTests</c> for how the vectors pin everything around them.
    /// </remarks>
    internal static HybridDataEncryptionService Deterministic() =>
        Service(new FixedDataKeyAndNonceSource(FormatTestData.DataKey(), FormatTestData.Nonce()));

    /// <summary>Encrypts a plaintext and returns the complete container.</summary>
    /// <param name="rsaPublicKeyPem">The recipient's RSA public key.</param>
    /// <param name="mlKemPublicKey">The recipient's raw ML-KEM public key.</param>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="parameterSet">The parameter set to encapsulate under.</param>
    /// <param name="service">The service to use; <see langword="null"/> builds a default one.</param>
    /// <returns>The container bytes.</returns>
    internal static async Task<byte[]> EncryptToBytesAsync(
        string rsaPublicKeyPem,
        byte[] mlKemPublicKey,
        byte[] plaintext,
        Cipher cipher = Cipher.Aes256Gcm,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        HybridDataEncryptionService? service = null)
    {
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await (service ?? Service()).EncryptAsync(
            input, output, cipher, rsaPublicKeyPem, mlKemPublicKey, parameterSet, null,
            CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>Decrypts a container and returns the recovered plaintext.</summary>
    /// <param name="rsaPrivateKeyPem">The recipient's RSA private key.</param>
    /// <param name="mlKemPrivateKey">The recipient's raw ML-KEM private key.</param>
    /// <param name="container">The container bytes.</param>
    /// <param name="rsaKeyPassword">The passphrase protecting <paramref name="rsaPrivateKeyPem"/>, if any.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <param name="service">The service to use; <see langword="null"/> builds a default one.</param>
    /// <returns>The recovered plaintext.</returns>
    internal static async Task<byte[]> DecryptToBytesAsync(
        string rsaPrivateKeyPem,
        byte[] mlKemPrivateKey,
        byte[] container,
        char[]? rsaKeyPassword = null,
        DataEncryptionLimits? limits = null,
        HybridDataEncryptionService? service = null)
    {
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();
        await (service ?? Service()).DecryptAsync(
            input, output, rsaPrivateKeyPem, mlKemPrivateKey, rsaKeyPassword, limits, null,
            CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>The RSAES-OAEP ciphertext carried by a container.</summary>
    /// <param name="container">The container bytes.</param>
    /// <param name="wrappedSecretLength">The wrapped-secret length <c>N</c>.</param>
    /// <returns>The <c>N</c> bytes at offset 22.</returns>
    internal static byte[] WrappedSecretOf(
        byte[] container,
        int wrappedSecretLength = WrappedSecretLength2048) =>
        container[WrappedSecretOffset..(WrappedSecretOffset + wrappedSecretLength)];

    /// <summary>The ML-KEM encapsulation carried by a container.</summary>
    /// <param name="container">The container bytes.</param>
    /// <param name="encapsulationLength">The encapsulation length <c>M</c>.</param>
    /// <param name="wrappedSecretLength">The wrapped-secret length <c>N</c>.</param>
    /// <returns>The <c>M</c> bytes at offset 26 + <c>N</c>.</returns>
    internal static byte[] EncapsulationOf(
        byte[] container,
        int encapsulationLength,
        int wrappedSecretLength = WrappedSecretLength2048)
    {
        int offset = EncapsulationOffset(wrappedSecretLength);
        return container[offset..(offset + encapsulationLength)];
    }

    /// <summary>The little-endian encoding of a 32-bit value, as the format writes it.</summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The four bytes.</returns>
    internal static byte[] LittleEndian(int value) =>
        [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];

    /// <summary>
    /// Builds a method-<c>0x05</c> header directly through <see cref="HeaderWriter"/>, for the cases a
    /// hostile <i>sender</i> could produce but the service itself never writes.
    /// </summary>
    /// <param name="parameterSet">The parameter set to record at offset 5.</param>
    /// <param name="wrappedRsaSecret">The RSAES-OAEP ciphertext to embed.</param>
    /// <param name="encapsulation">The encapsulation to embed.</param>
    /// <param name="dataKey">The key the confirmation tag is computed under.</param>
    /// <param name="cipher">The cipher byte to record.</param>
    /// <returns>The complete header bytes.</returns>
    /// <remarks>
    /// <paramref name="dataKey"/> is deliberately independent of the two ciphertexts here. That is what
    /// lets a test seal a header under a key the recipient will <i>not</i> arrive at — the only way to
    /// isolate one combiner input while holding the transcript fixed.
    /// </remarks>
    internal static async Task<byte[]> BuildHeaderAsync(
        MLKemParameterSet parameterSet,
        byte[] wrappedRsaSecret,
        byte[] encapsulation,
        byte[] dataKey,
        Cipher cipher = Cipher.Aes256Gcm)
    {
        using MemoryStream output = new();
        return await HeaderWriter.WriteHybridHeaderAsync(
            output,
            cipher,
            parameterSet,
            FormatTestData.Nonce(),
            wrappedRsaSecret,
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

    /// <summary>The committed golden plaintext — the same 45 bytes every other method's vectors use.</summary>
    /// <returns>The plaintext bytes.</returns>
    internal static byte[] GoldenPlaintext() => ContainerFixtures.Read("golden-plaintext.txt");

    /// <summary>The committed RSA-2048 public key, shared with the RSA golden vectors.</summary>
    /// <returns>The PEM text.</returns>
    internal static string GoldenRsaPublicKeyPem() => RsaTestData.GoldenPublicKeyPem();

    /// <summary>The committed RSA-2048 private key, unencrypted.</summary>
    /// <returns>The PEM text.</returns>
    internal static string GoldenRsaPrivateKeyPem() => RsaTestData.GoldenPrivateKeyPem();

    /// <summary>The same committed private key in a PKCS#8 encrypted PEM.</summary>
    /// <returns>The PEM text.</returns>
    internal static string GoldenEncryptedRsaPrivateKeyPem() => RsaTestData.GoldenEncryptedPrivateKeyPem();

    /// <summary>A fresh copy of <see cref="GoldenPemPassphrase"/> as characters.</summary>
    /// <returns>The passphrase characters.</returns>
    internal static char[] GoldenPemPassphraseChars() => RsaTestData.GoldenPemPassphraseChars();

    /// <summary>The committed golden ML-KEM public key, shared with the ML-KEM golden vectors.</summary>
    /// <param name="slug">The fixture slug — <c>512</c> or <c>1024</c>.</param>
    /// <returns>The raw FIPS 203 public key.</returns>
    internal static byte[] GoldenMLKemPublicKey(string slug) => MLKemTestData.GoldenPublicKey(slug);

    /// <summary>The committed golden ML-KEM private key.</summary>
    /// <param name="slug">The fixture slug — <c>512</c> or <c>1024</c>.</param>
    /// <returns>The raw expanded FIPS 203 private key.</returns>
    internal static byte[] GoldenMLKemPrivateKey(string slug) => MLKemTestData.GoldenPrivateKey(slug);

    /// <summary>
    /// The committed ML-KEM shared secret that <c>hybrid-aes.bin</c>'s and <c>hybrid-twofish.bin</c>'s
    /// encapsulation yields — the KEM half of the combiner's input, pinned as a constant because the write
    /// path cannot pin it.
    /// </summary>
    /// <returns>The 32-byte shared secret.</returns>
    internal static byte[] GoldenKemSecret() => ContainerFixtures.Read("hybrid-kem-secret.bin");

    /// <summary>Wraps arbitrary bytes under a public key with the OAEP parameters the format fixes.</summary>
    /// <param name="data">The bytes to wrap.</param>
    /// <param name="publicKeyPem">The recipient's public key.</param>
    /// <returns>The OAEP ciphertext.</returns>
    internal static byte[] WrapOaep(byte[] data, string publicKeyPem) =>
        RsaTestData.WrapOaep(data, publicKeyPem);

    /// <summary>Unwraps with the OAEP parameters the format fixes.</summary>
    /// <param name="wrappedSecret">The OAEP ciphertext.</param>
    /// <param name="privateKeyPem">The recipient's private key.</param>
    /// <param name="keyPassword">The passphrase protecting the PEM, if any.</param>
    /// <returns>The recovered bytes.</returns>
    internal static byte[] UnwrapOaep(byte[] wrappedSecret, string privateKeyPem, char[]? keyPassword = null) =>
        RsaTestData.UnwrapOaep(wrappedSecret, privateKeyPem, keyPassword);

    /// <summary>Encapsulates against a public key with Enigma.Core's ML-KEM directly.</summary>
    /// <param name="publicKey">The recipient's public key.</param>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The encapsulation and the shared secret.</returns>
    internal static (byte[] Encapsulation, byte[] SharedSecret) Encapsulate(
        byte[] publicKey,
        MLKemParameterSet parameterSet) =>
        MLKemTestData.Encapsulate(publicKey, parameterSet);

    /// <summary>Recovers a shared secret with Enigma.Core's ML-KEM directly, bypassing this library.</summary>
    /// <param name="encapsulation">The encapsulation.</param>
    /// <param name="privateKey">The recipient's private key.</param>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The 32-byte shared secret.</returns>
    internal static byte[] Decapsulate(
        byte[] encapsulation,
        byte[] privateKey,
        MLKemParameterSet parameterSet) =>
        MLKemTestData.Decapsulate(encapsulation, privateKey, parameterSet);

    /// <summary>
    /// Runs the library's own key combiner, for the tests that need the value the service will arrive at.
    /// </summary>
    /// <param name="rsaSecret">The 32-byte secret the RSAES-OAEP ciphertext carries.</param>
    /// <param name="kemSecret">The 32-byte FIPS 203 shared secret.</param>
    /// <param name="wrappedRsaSecret">The RSAES-OAEP ciphertext.</param>
    /// <param name="encapsulation">The ML-KEM encapsulation.</param>
    /// <returns>The 32-byte combined data key.</returns>
    /// <remarks>
    /// Use <c>GoldenVectorPrimitives.HybridDataKey</c> instead wherever the expectation must be
    /// <i>independent</i> of the library; this one is for building hostile containers, where what matters
    /// is what the reader will compute rather than what the specification says.
    /// </remarks>
    internal static byte[] Combine(
        byte[] rsaSecret,
        byte[] kemSecret,
        byte[] wrappedRsaSecret,
        byte[] encapsulation) =>
        HybridKeyCombiner.Combine(
            FormatTestData.HmacSha256(), rsaSecret, kemSecret, wrappedRsaSecret, encapsulation);
}
