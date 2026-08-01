using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption;

/// <summary>
/// The default <see cref="IRsaDataEncryptionService"/>, implementing container method <c>0x03</c> on
/// top of Enigma.Core's public-key, HMAC and block-cipher services.
/// </summary>
/// <remarks>
/// Stateless and safe for concurrent use; registered as a singleton by
/// <see cref="Microsoft.Extensions.DependencyInjection.ServiceCollectionExtensions.AddEnigmaDataEncryption"/>.
/// </remarks>
public sealed class RsaDataEncryptionService : IRsaDataEncryptionService
{
    private readonly IBlockCipherServiceFactory _blockCipherServiceFactory;
    private readonly IPublicKeyServiceFactory _publicKeyServiceFactory;
    private readonly IHmacServiceFactory _hmacServiceFactory;
    private readonly IRandomSource _randomSource;

    /// <summary>
    /// Initializes a new instance backed by Enigma.Core's default factories, for use without a
    /// dependency-injection container.
    /// </summary>
    public RsaDataEncryptionService()
        : this(new BlockCipherServiceFactory(), new PublicKeyServiceFactory(), new HmacServiceFactory())
    {
    }

    /// <summary>
    /// Initializes a new instance with caller-supplied Enigma.Core factories. This is the constructor
    /// a dependency-injection container resolves.
    /// </summary>
    /// <param name="blockCipherServiceFactory">Supplies the AEAD block cipher selected by the container's cipher byte.</param>
    /// <param name="publicKeyServiceFactory">Supplies the RSA service that wraps and unwraps the data key.</param>
    /// <param name="hmacServiceFactory">Supplies the HMAC-SHA256 service backing key confirmation.</param>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    public RsaDataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IPublicKeyServiceFactory publicKeyServiceFactory,
        IHmacServiceFactory hmacServiceFactory)
        : this(blockCipherServiceFactory, publicKeyServiceFactory, hmacServiceFactory, new RandomSource())
    {
    }

    // Test seam: lets the golden-vector suite pin the encrypt path byte-for-byte by supplying a
    // deterministic data key and nonce. Internal by design — see IRandomSource.
    internal RsaDataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IPublicKeyServiceFactory publicKeyServiceFactory,
        IHmacServiceFactory hmacServiceFactory,
        IRandomSource randomSource)
    {
        _blockCipherServiceFactory = blockCipherServiceFactory ?? throw new ArgumentNullException(nameof(blockCipherServiceFactory));
        _publicKeyServiceFactory = publicKeyServiceFactory ?? throw new ArgumentNullException(nameof(publicKeyServiceFactory));
        _hmacServiceFactory = hmacServiceFactory ?? throw new ArgumentNullException(nameof(hmacServiceFactory));
        _randomSource = randomSource ?? throw new ArgumentNullException(nameof(randomSource));
    }

    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string publicKeyPem,
        RsaOaepHash oaepHash = RsaOaepHash.Sha256,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Validation is synchronous — an argument mistake faults the call, not the returned task — and
        // runs in declaration order, so the first parameter at fault is the one reported.
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        ValidatePem(publicKeyPem, nameof(publicKeyPem));
        RsaOaepHashWire.ValidateArgument(oaepHash, nameof(oaepHash));

        return EncryptCoreAsync(input, output, cipher, publicKeyPem, oaepHash, progress, cancellationToken);
    }

    /// <inheritdoc />
    public Task DecryptAsync(
        Stream input,
        Stream output,
        string privateKeyPem,
        char[]? keyPassword = null,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        ValidatePem(privateKeyPem, nameof(privateKeyPem));

        return DecryptCoreAsync(input, output, privateKeyPem, keyPassword, limits, progress, cancellationToken);
    }

    /// <summary>
    /// The encrypt half of the canonical order (<c>docs/format.md</c> §7.1): data key and nonce, wrap,
    /// header, tag, write, payload — with the data key cleared in a <c>finally</c> that encloses every
    /// use of it.
    /// </summary>
    /// <remarks>
    /// The wrap comes before the header is built, and therefore before anything is written: a public key
    /// Enigma.Core cannot use — including one too small for <paramref name="oaepHash"/> — leaves the
    /// output stream untouched.
    /// </remarks>
    private async Task EncryptCoreAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string publicKeyPem,
        RsaOaepHash oaepHash,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] nonce = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.NonceSizeBytes);

        byte[]? dataKey = null;
        try
        {
            // Unlike the password methods, the data key is generated rather than derived: RSA transports
            // it, so it never needs to be reproducible from a credential.
            dataKey = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.DataKeySizeBytes);

            byte[] wrappedKey = WrapDataKey(dataKey, publicKeyPem, oaepHash);

            byte[] header = await HeaderWriter.WriteRsaHeaderAsync(
                output,
                cipher,
                oaepHash,
                nonce,
                wrappedKey,
                dataKey,
                _hmacServiceFactory.CreateHmacSha256Service(),
                cancellationToken).ConfigureAwait(false);

            await PayloadCipher.EncryptAsync(
                _blockCipherServiceFactory,
                cipher,
                input,
                output,
                dataKey,
                nonce,
                header,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptoHelpers.Clear(dataKey);
        }
    }

    /// <summary>
    /// The decrypt half of the canonical order (<c>docs/format.md</c> §7.2): parse and bound the header,
    /// unwrap, confirm the key, then — and only then — touch the payload.
    /// </summary>
    private async Task DecryptCoreAsync(
        Stream input,
        Stream output,
        string privateKeyPem,
        char[]? keyPassword,
        DataEncryptionLimits? limits,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            input,
            EncryptionMethod.Rsa,
            limits ?? DataEncryptionLimits.Default,
            cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        // Non-null for method 0x03: HeaderReader populates it, bounded by MaxWrappedKeyLength, or throws.
        byte[] wrappedKey = parsed.WrappedKey!;

        byte[]? dataKey = null;
        try
        {
            // Non-null for method 0x03 too: the reader resolves offset 5 or throws. The hash comes from
            // the container, never from the caller — docs/format.md §3.3.
            dataKey = UnwrapDataKey(wrappedKey, privateKeyPem, parsed.RsaOaepHash!.Value, keyPassword);

            if (!KeyConfirmation.Verify(
                    _hmacServiceFactory.CreateHmacSha256Service(),
                    dataKey,
                    parsed.BytesBeforeTag,
                    parsed.KeyConfirmationTag))
            {
                throw new DataDecryptionException(
                    "The RSA private key is wrong: the container's key-confirmation tag does not match the unwrapped data key. No payload byte was read.");
            }

            await PayloadCipher.DecryptAsync(
                _blockCipherServiceFactory,
                parsed.Header.Cipher,
                input,
                output,
                dataKey,
                parsed.Nonce,
                parsed.HeaderBytes,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptoHelpers.Clear(dataKey);
        }
    }

    /// <summary>
    /// Wraps the data key under the recipient's public key with the selected OAEP hash, translating a
    /// public key Enigma.Core cannot wrap with into an argument error.
    /// </summary>
    /// <param name="dataKey">The 32-byte data key to transport.</param>
    /// <param name="publicKeyPem">The recipient's public key, PEM-encoded.</param>
    /// <param name="oaepHash">The OAEP padding hash, already validated.</param>
    /// <returns>The OAEP ciphertext, whose length becomes the header's <c>N</c>.</returns>
    /// <remarks>
    /// <para>
    /// <b>A modulus too small for the hash is the caller's public key being unusable, so it is reported
    /// that way.</b> RFC 8017 §7.1.1 needs <c>k &gt;= 2·hLen + 34</c> to wrap 32 bytes — 98 bytes for
    /// SHA-256, 130 for SHA-384, 162 for SHA-512 — and Enigma.Core reports a shortfall as
    /// <see cref="CryptographicException"/>. This is the encrypt side, where the public key is the only
    /// thing the caller supplied that the operation can be about, so the failure becomes
    /// <see cref="ArgumentException"/> on <paramref name="publicKeyPem"/> with the original kept as
    /// <see cref="Exception.InnerException"/> — matching what <c>docs/format.md</c> §9 already prescribes
    /// for ML-KEM's <c>Encapsulate</c>.
    /// </para>
    /// <para>
    /// Pre-validating the modulus instead is not available: Enigma.Core exposes no modulus-size accessor,
    /// and this library parses no PEM of its own (it takes no direct BouncyCastle dependency, and
    /// <c>netstandard2.0</c> offers no PEM/RSA parser). Translation is the only option.
    /// </para>
    /// </remarks>
    private byte[] WrapDataKey(byte[] dataKey, string publicKeyPem, RsaOaepHash oaepHash)
    {
        try
        {
            return _publicKeyServiceFactory.CreatePublicKeyService()
                .EncryptOaep(dataKey, publicKeyPem, oaepHash);
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException(
                $"The RSA public key cannot wrap a {DataEncryptionDefaults.DataKeySizeBytes}-byte data key under OAEP-{oaepHash}. The modulus must be at least 2*hLen + 34 bytes (RFC 8017 §7.1.1): 98 for SHA-256, 130 for SHA-384, 162 for SHA-512.",
                nameof(publicKeyPem),
                exception);
        }
    }

    /// <summary>
    /// Recovers the data key from the header's wrapped key with the OAEP hash the header names,
    /// translating an unwrap failure and rejecting anything that is not a 32-byte key.
    /// </summary>
    /// <param name="wrappedKey">The wrapped key read from the header.</param>
    /// <param name="privateKeyPem">The recipient's private key, PEM-encoded.</param>
    /// <param name="oaepHash">The OAEP padding hash read from header offset 5.</param>
    /// <param name="keyPassword">The passphrase protecting <paramref name="privateKeyPem"/>, or <see langword="null"/>.</param>
    /// <returns>The 32-byte data key.</returns>
    /// <remarks>
    /// <para>
    /// <b>Every OAEP failure becomes a decryption error, including an undecryptable private-key PEM.</b>
    /// Enigma.Core reports a wrong private key, a wrongly-passworded PEM, an encrypted PEM with no
    /// passphrase and a container whose OAEP-hash byte was edited as the <i>same</i>
    /// <see cref="CryptographicException"/> from the <i>same</i> call, so
    /// they cannot be told apart without matching on message text. They are therefore all wrapped, with
    /// the original kept as <see cref="Exception.InnerException"/> — which is where the specific cause
    /// remains readable (<c>docs/format.md</c> §9). A PEM that cannot be <i>parsed</i> at all still
    /// propagates untouched, as <see cref="ArgumentException"/>: that distinction survives, because the
    /// type is unambiguous. §9 also permits <see cref="FormatException"/>, which Enigma.Core 1.1.0 no
    /// longer raises for an invalid-Base64 PEM but keeps nested inside the
    /// <see cref="ArgumentException"/>.
    /// </para>
    /// <para>
    /// The length check guards the one thing OAEP does not: a hostile sender holding the recipient's
    /// public key can wrap any number of bytes, and a short "data key" would otherwise reach the block
    /// cipher and surface as an unwrapped Enigma.Core exception. Key confirmation is no defence here —
    /// whoever chose the key material can compute a matching tag.
    /// </para>
    /// </remarks>
    private byte[] UnwrapDataKey(
        byte[] wrappedKey,
        string privateKeyPem,
        RsaOaepHash oaepHash,
        char[]? keyPassword)
    {
        byte[] dataKey;
        try
        {
            dataKey = _publicKeyServiceFactory.CreatePublicKeyService()
                .DecryptOaep(wrappedKey, privateKeyPem, oaepHash, keyPassword);
        }
        catch (CryptographicException exception)
        {
            throw new DataDecryptionException(
                "The RSA private key does not open this container: the wrapped data key could not be recovered. The key may not match the container, an encrypted private-key PEM may have been supplied with the wrong passphrase, or the container's OAEP-hash byte may have been edited.",
                exception);
        }

        if (dataKey.Length != DataEncryptionDefaults.DataKeySizeBytes)
        {
            CryptoHelpers.Clear(dataKey);

            throw new DataEncryptionFormatException(
                $"The container's wrapped key holds {dataKey.Length} bytes; a method 0x03 container must wrap a {DataEncryptionDefaults.DataKeySizeBytes}-byte data key.");
        }

        return dataKey;
    }

    private static void ValidatePem(string pem, string paramName)
    {
        if (pem is null) throw new ArgumentNullException(paramName);

        if (pem.Length == 0)
        {
            throw new ArgumentException("The PEM-encoded key must not be empty.", paramName);
        }
    }
}
