using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption;

/// <summary>
/// The default <see cref="IHybridDataEncryptionService"/>, implementing container method <c>0x05</c> on
/// top of Enigma.Core's public-key, ML-KEM, HMAC and block-cipher services.
/// </summary>
/// <remarks>
/// <para>
/// The only service that drives two key-establishment primitives per call. It is deliberately <b>not</b>
/// composed from <see cref="RsaDataEncryptionService"/> and <see cref="MLKemDataEncryptionService"/>:
/// those each write a complete container of their own method, while this one needs the two primitives'
/// intermediate outputs — both secrets and both ciphertexts — to reach
/// <see cref="HybridKeyCombiner"/> before a single header byte exists.
/// </para>
/// <para>
/// Stateless and safe for concurrent use; registered as a singleton by
/// <see cref="Microsoft.Extensions.DependencyInjection.ServiceCollectionExtensions.AddEnigmaDataEncryption"/>.
/// </para>
/// </remarks>
public sealed class HybridDataEncryptionService : IHybridDataEncryptionService
{
    private readonly IBlockCipherServiceFactory _blockCipherServiceFactory;
    private readonly IPublicKeyServiceFactory _publicKeyServiceFactory;
    private readonly IMLKemServiceFactory _mlKemServiceFactory;
    private readonly IHmacServiceFactory _hmacServiceFactory;
    private readonly IRandomSource _randomSource;

    /// <summary>
    /// Initializes a new instance backed by Enigma.Core's default factories, for use without a
    /// dependency-injection container.
    /// </summary>
    public HybridDataEncryptionService()
        : this(
            new BlockCipherServiceFactory(),
            new PublicKeyServiceFactory(),
            new MLKemServiceFactory(),
            new HmacServiceFactory())
    {
    }

    /// <summary>
    /// Initializes a new instance with caller-supplied Enigma.Core factories. This is the constructor
    /// a dependency-injection container resolves.
    /// </summary>
    /// <param name="blockCipherServiceFactory">Supplies the AEAD block cipher selected by the container's cipher byte.</param>
    /// <param name="publicKeyServiceFactory">Supplies the RSA service that wraps and unwraps the RSA half's secret.</param>
    /// <param name="mlKemServiceFactory">Supplies the ML-KEM service for the container's parameter set.</param>
    /// <param name="hmacServiceFactory">Supplies the HMAC-SHA256 service backing both the key combiner and key confirmation.</param>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    public HybridDataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IPublicKeyServiceFactory publicKeyServiceFactory,
        IMLKemServiceFactory mlKemServiceFactory,
        IHmacServiceFactory hmacServiceFactory)
        : this(
            blockCipherServiceFactory,
            publicKeyServiceFactory,
            mlKemServiceFactory,
            hmacServiceFactory,
            new RandomSource())
    {
    }

    // Test seam: lets the golden-vector suite pin the encrypt path byte-for-byte by supplying a
    // deterministic nonce and RSA-half secret. Internal by design — see IRandomSource.
    internal HybridDataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IPublicKeyServiceFactory publicKeyServiceFactory,
        IMLKemServiceFactory mlKemServiceFactory,
        IHmacServiceFactory hmacServiceFactory,
        IRandomSource randomSource)
    {
        _blockCipherServiceFactory = blockCipherServiceFactory ?? throw new ArgumentNullException(nameof(blockCipherServiceFactory));
        _publicKeyServiceFactory = publicKeyServiceFactory ?? throw new ArgumentNullException(nameof(publicKeyServiceFactory));
        _mlKemServiceFactory = mlKemServiceFactory ?? throw new ArgumentNullException(nameof(mlKemServiceFactory));
        _hmacServiceFactory = hmacServiceFactory ?? throw new ArgumentNullException(nameof(hmacServiceFactory));
        _randomSource = randomSource ?? throw new ArgumentNullException(nameof(randomSource));
    }

    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string rsaPublicKeyPem,
        byte[] mlKemPublicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Validation is synchronous — an argument mistake faults the call, not the returned task — and
        // runs in declaration order, so the first parameter at fault is the one reported.
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        ValidatePem(rsaPublicKeyPem, nameof(rsaPublicKeyPem));
        ValidateKemKey(mlKemPublicKey, nameof(mlKemPublicKey));
        MLKemParameterSetWire.ValidateArgument(parameterSet, nameof(parameterSet));

        return EncryptCoreAsync(
            input, output, cipher, rsaPublicKeyPem, mlKemPublicKey, parameterSet, progress, cancellationToken);
    }

    /// <inheritdoc />
    public Task DecryptAsync(
        Stream input,
        Stream output,
        string rsaPrivateKeyPem,
        byte[] mlKemPrivateKey,
        char[]? rsaKeyPassword = null,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        ValidatePem(rsaPrivateKeyPem, nameof(rsaPrivateKeyPem));
        ValidateKemKey(mlKemPrivateKey, nameof(mlKemPrivateKey));

        return DecryptCoreAsync(
            input, output, rsaPrivateKeyPem, mlKemPrivateKey, rsaKeyPassword, limits, progress,
            cancellationToken);
    }

    /// <summary>
    /// The encrypt half of the canonical order (<c>docs/format.md</c> §7.1): nonce and RSA-half secret,
    /// wrap, encapsulate, combine, header, tag, write, payload — with all three pieces of key material
    /// cleared in a <c>finally</c> that encloses every use of them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both public-key operations precede the header, and therefore every write.</b> A public key
    /// Enigma.Core cannot use — either of the two — leaves the output stream untouched. The wrap runs
    /// first only because the RSA half's secret has to exist before there is anything to wrap; nothing
    /// downstream depends on the order.
    /// </para>
    /// <para>
    /// The combiner needs both ciphertexts, and the key-confirmation tag needs the combined key, so the
    /// ordering is forced and non-circular: wrap and encapsulate, combine, then build and seal the header
    /// (§3.5.1, §6).
    /// </para>
    /// </remarks>
    private async Task EncryptCoreAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string rsaPublicKeyPem,
        byte[] mlKemPublicKey,
        MLKemParameterSet parameterSet,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] nonce = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.NonceSizeBytes);

        byte[]? rsaSecret = null;
        byte[]? kemSecret = null;
        byte[]? dataKey = null;
        try
        {
            // The RSA half transports a freshly generated secret, exactly as method 0x03 transports its
            // data key; the ML-KEM half generates nothing, because encapsulation produces its secret.
            rsaSecret = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.DataKeySizeBytes);

            byte[] wrappedRsaSecret = _publicKeyServiceFactory.CreatePublicKeyService()
                .EncryptOaep(rsaSecret, rsaPublicKeyPem, RsaOaepHash.Sha256);

            byte[] encapsulation;
            (encapsulation, kemSecret) = Encapsulate(mlKemPublicKey, parameterSet);

            dataKey = HybridKeyCombiner.Combine(
                _hmacServiceFactory.CreateHmacSha256Service(),
                rsaSecret,
                kemSecret,
                wrappedRsaSecret,
                encapsulation);

            byte[] header = await HeaderWriter.WriteHybridHeaderAsync(
                output,
                cipher,
                parameterSet,
                nonce,
                wrappedRsaSecret,
                encapsulation,
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
            CryptoHelpers.Clear(rsaSecret, kemSecret, dataKey);
        }
    }

    /// <summary>
    /// The decrypt half of the canonical order (<c>docs/format.md</c> §7.2): parse and bound the header,
    /// unwrap, decapsulate, combine, confirm the key, then — and only then — touch the payload.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The unwrap runs before the decapsulation, and that is what shapes the failure modes.</b> A
    /// wrong RSA private key is reported by OAEP, so it never reaches key confirmation; a wrong ML-KEM
    /// private key is reported by nothing at all — FIPS 203 implicit rejection makes its decapsulation
    /// succeed with a different secret — so the key-confirmation tag over the <i>combined</i> key is the
    /// only check that can catch it (§6.3). When both keys are wrong, the RSA failure is the one the
    /// caller sees.
    /// </para>
    /// <para>
    /// All three pieces of key material are cleared in the <c>finally</c>, including the secrets a wrong
    /// credential produced: a wrong secret is still key material.
    /// </para>
    /// </remarks>
    private async Task DecryptCoreAsync(
        Stream input,
        Stream output,
        string rsaPrivateKeyPem,
        byte[] mlKemPrivateKey,
        char[]? rsaKeyPassword,
        DataEncryptionLimits? limits,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            input,
            EncryptionMethod.Hybrid,
            limits ?? DataEncryptionLimits.Default,
            cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        // All three are non-null for method 0x05: HeaderReader populates them — the parameter set from
        // offset 5, and the two ciphertexts bounded by MaxWrappedKeyLength and MaxEncapsulationLength —
        // or throws.
        byte[] wrappedRsaSecret = parsed.WrappedKey!;
        byte[] encapsulation = parsed.Encapsulation!;
        MLKemParameterSet parameterSet = parsed.MLKemParameterSet!.Value;

        byte[]? rsaSecret = null;
        byte[]? kemSecret = null;
        byte[]? dataKey = null;
        try
        {
            rsaSecret = UnwrapRsaSecret(wrappedRsaSecret, rsaPrivateKeyPem, rsaKeyPassword);
            kemSecret = Decapsulate(encapsulation, mlKemPrivateKey, parameterSet);

            dataKey = HybridKeyCombiner.Combine(
                _hmacServiceFactory.CreateHmacSha256Service(),
                rsaSecret,
                kemSecret,
                wrappedRsaSecret,
                encapsulation);

            if (!KeyConfirmation.Verify(
                    _hmacServiceFactory.CreateHmacSha256Service(),
                    dataKey,
                    parsed.BytesBeforeTag,
                    parsed.KeyConfirmationTag))
            {
                throw new DataDecryptionException(
                    "One of the two hybrid private keys is wrong: the container's key-confirmation tag does not match the data key combined from the recovered secrets. The RSA secret unwrapped and the ML-KEM secret decapsulated, so neither primitive could report this — for ML-KEM, FIPS 203 implicit rejection means decapsulation with a wrong key succeeds. No payload byte was read.");
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
            CryptoHelpers.Clear(rsaSecret, kemSecret, dataKey);
        }
    }

    /// <summary>
    /// Encapsulates a fresh shared secret against the recipient's ML-KEM public key, translating an
    /// encapsulation failure into the argument error it can only be.
    /// </summary>
    /// <param name="mlKemPublicKey">The recipient's raw FIPS 203 encapsulation key.</param>
    /// <param name="parameterSet">The parameter set to encapsulate under.</param>
    /// <returns>The encapsulation to write into the header, and the 32-byte shared secret to combine.</returns>
    /// <exception cref="ArgumentException"><paramref name="mlKemPublicKey"/> is malformed or is not a key for <paramref name="parameterSet"/>.</exception>
    /// <remarks>
    /// The same translation <see cref="MLKemDataEncryptionService"/> makes, and for the same reason:
    /// <see cref="IMLKemService.Encapsulate"/> takes the public key and nothing else, so a failure can
    /// only be about the key the caller supplied. The decrypt side is deliberately not symmetrical — see
    /// <see cref="Decapsulate"/>.
    /// </remarks>
    private (byte[] Encapsulation, byte[] SharedSecret) Encapsulate(
        byte[] mlKemPublicKey,
        MLKemParameterSet parameterSet)
    {
        try
        {
            return _mlKemServiceFactory.CreateMLKemService(parameterSet).Encapsulate(mlKemPublicKey);
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException(
                $"The ML-KEM public key could not be used to encapsulate a shared secret. It is malformed, or it is not a {parameterSet} key.",
                nameof(mlKemPublicKey),
                exception);
        }
    }

    /// <summary>
    /// Recovers the RSA half's secret from the header's ciphertext with RSAES-OAEP-SHA256, translating an
    /// unwrap failure and rejecting anything that is not 32 bytes.
    /// </summary>
    /// <param name="wrappedRsaSecret">The RSAES-OAEP ciphertext read from the header.</param>
    /// <param name="rsaPrivateKeyPem">The recipient's RSA private key, PEM-encoded.</param>
    /// <param name="rsaKeyPassword">The passphrase protecting <paramref name="rsaPrivateKeyPem"/>, or <see langword="null"/>.</param>
    /// <returns>The 32-byte secret.</returns>
    /// <remarks>
    /// <para>
    /// The same two rules <see cref="RsaDataEncryptionService"/> applies, for the same reasons: every OAEP
    /// failure — a wrong private key, a wrongly-passworded PEM, an encrypted PEM with no passphrase —
    /// becomes a <see cref="DataDecryptionException"/> with the cause preserved, because Enigma.Core
    /// reports all of them identically; while a PEM that cannot be <i>parsed</i> keeps its own
    /// <see cref="ArgumentException"/> or <see cref="FormatException"/> and propagates untouched
    /// (<c>docs/format.md</c> §9).
    /// </para>
    /// <para>
    /// The length check matters here for the same reason it does for method <c>0x03</c>: a sender holding
    /// the recipient's public key chooses what gets wrapped, and a short "secret" would otherwise reach
    /// the combiner. Key confirmation is no defence, since whoever chose the secret can compute a
    /// matching tag.
    /// </para>
    /// </remarks>
    private byte[] UnwrapRsaSecret(byte[] wrappedRsaSecret, string rsaPrivateKeyPem, char[]? rsaKeyPassword)
    {
        byte[] rsaSecret;
        try
        {
            rsaSecret = _publicKeyServiceFactory.CreatePublicKeyService()
                .DecryptOaep(wrappedRsaSecret, rsaPrivateKeyPem, RsaOaepHash.Sha256, rsaKeyPassword);
        }
        catch (CryptographicException exception)
        {
            throw new DataDecryptionException(
                "The RSA private key does not open this container: the wrapped secret could not be recovered. The key may not match the container, or an encrypted private-key PEM may have been supplied with the wrong passphrase.",
                exception);
        }

        if (rsaSecret.Length != DataEncryptionDefaults.DataKeySizeBytes)
        {
            CryptoHelpers.Clear(rsaSecret);

            throw new DataEncryptionFormatException(
                $"The container's RSAES-OAEP ciphertext holds {rsaSecret.Length} bytes; a method 0x05 container must wrap a {DataEncryptionDefaults.DataKeySizeBytes}-byte secret.");
        }

        return rsaSecret;
    }

    /// <summary>
    /// Recovers the ML-KEM half's shared secret from the header's encapsulation, translating a
    /// decapsulation failure.
    /// </summary>
    /// <param name="encapsulation">The encapsulation read from the header.</param>
    /// <param name="mlKemPrivateKey">The recipient's raw FIPS 203 decapsulation key.</param>
    /// <param name="parameterSet">The parameter set recorded at header offset 5.</param>
    /// <returns>The 32-byte shared secret.</returns>
    /// <exception cref="DataDecryptionException">The private key and the container's encapsulation cannot be combined.</exception>
    /// <remarks>
    /// The same translation <see cref="MLKemDataEncryptionService"/> makes: Enigma.Core raises one
    /// <see cref="CryptographicException"/> for a malformed private key, a key for another parameter set,
    /// and a container whose parameter-set byte was edited, so all three are wrapped rather than guessed
    /// at from message text (<c>docs/format.md</c> §9). No length check on the result: FIPS 203 fixes the
    /// shared-secret length at 32 bytes independently of the ciphertext, so no sender can influence it.
    /// </remarks>
    private byte[] Decapsulate(byte[] encapsulation, byte[] mlKemPrivateKey, MLKemParameterSet parameterSet)
    {
        try
        {
            return _mlKemServiceFactory.CreateMLKemService(parameterSet)
                .Decapsulate(encapsulation, mlKemPrivateKey);
        }
        catch (CryptographicException exception)
        {
            throw new DataDecryptionException(
                $"The ML-KEM private key does not open this container: the shared secret could not be decapsulated. The key may be malformed, or it may not be a {parameterSet} key — which is what the container's parameter-set byte claims it was encapsulated under.",
                exception);
        }
    }

    private static void ValidatePem(string pem, string paramName)
    {
        if (pem is null) throw new ArgumentNullException(paramName);

        if (pem.Length == 0)
        {
            throw new ArgumentException("The PEM-encoded key must not be empty.", paramName);
        }
    }

    private static void ValidateKemKey(byte[] key, string paramName)
    {
        if (key is null) throw new ArgumentNullException(paramName);

        if (key.Length == 0)
        {
            throw new ArgumentException("The ML-KEM key must not be empty.", paramName);
        }
    }
}
