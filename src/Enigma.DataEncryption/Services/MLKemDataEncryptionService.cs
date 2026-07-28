using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption;

/// <summary>
/// The default <see cref="IMLKemDataEncryptionService"/>, implementing container method <c>0x04</c>
/// on top of Enigma.Core's ML-KEM, HMAC and block-cipher services.
/// </summary>
/// <remarks>
/// Stateless and safe for concurrent use; registered as a singleton by
/// <see cref="Microsoft.Extensions.DependencyInjection.ServiceCollectionExtensions.AddEnigmaDataEncryption"/>.
/// </remarks>
// ReSharper disable once InconsistentNaming
public sealed class MLKemDataEncryptionService : IMLKemDataEncryptionService
{
    private readonly IBlockCipherServiceFactory _blockCipherServiceFactory;
    private readonly IMLKemServiceFactory _mlKemServiceFactory;
    private readonly IHmacServiceFactory _hmacServiceFactory;
    private readonly IRandomSource _randomSource;

    /// <summary>
    /// Initializes a new instance backed by Enigma.Core's default factories, for use without a
    /// dependency-injection container.
    /// </summary>
    public MLKemDataEncryptionService()
        : this(new BlockCipherServiceFactory(), new MLKemServiceFactory(), new HmacServiceFactory())
    {
    }

    /// <summary>
    /// Initializes a new instance with caller-supplied Enigma.Core factories. This is the constructor
    /// a dependency-injection container resolves.
    /// </summary>
    /// <param name="blockCipherServiceFactory">Supplies the AEAD block cipher selected by the container's cipher byte.</param>
    /// <param name="mlKemServiceFactory">Supplies the ML-KEM service for the container's parameter set.</param>
    /// <param name="hmacServiceFactory">Supplies the HMAC-SHA256 service backing key confirmation.</param>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    public MLKemDataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IMLKemServiceFactory mlKemServiceFactory,
        IHmacServiceFactory hmacServiceFactory)
        : this(blockCipherServiceFactory, mlKemServiceFactory, hmacServiceFactory, new RandomSource())
    {
    }

    // Test seam: lets the golden-vector suite pin the encrypt path byte-for-byte by supplying a
    // deterministic nonce. Internal by design — see IRandomSource.
    internal MLKemDataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IMLKemServiceFactory mlKemServiceFactory,
        IHmacServiceFactory hmacServiceFactory,
        IRandomSource randomSource)
    {
        _blockCipherServiceFactory = blockCipherServiceFactory ?? throw new ArgumentNullException(nameof(blockCipherServiceFactory));
        _mlKemServiceFactory = mlKemServiceFactory ?? throw new ArgumentNullException(nameof(mlKemServiceFactory));
        _hmacServiceFactory = hmacServiceFactory ?? throw new ArgumentNullException(nameof(hmacServiceFactory));
        _randomSource = randomSource ?? throw new ArgumentNullException(nameof(randomSource));
    }

    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] publicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Validation is synchronous — an argument mistake faults the call, not the returned task — and
        // runs in declaration order, so the first parameter at fault is the one reported.
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        ValidateKey(publicKey, nameof(publicKey));
        MLKemParameterSetWire.ValidateArgument(parameterSet, nameof(parameterSet));

        return EncryptCoreAsync(input, output, cipher, publicKey, parameterSet, progress, cancellationToken);
    }

    /// <inheritdoc />
    public Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] privateKey,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        ValidateKey(privateKey, nameof(privateKey));

        return DecryptCoreAsync(input, output, privateKey, limits, progress, cancellationToken);
    }

    /// <summary>
    /// The encrypt half of the canonical order (<c>docs/format.md</c> §7.1): nonce, encapsulate, header, tag,
    /// write, payload — with the shared secret cleared in a <c>finally</c> that encloses every use of it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The data key is never generated here.</b> Encapsulation produces it: the 32-byte FIPS 203 shared
    /// secret <i>is</i> the data key, with no further derivation (<c>docs/format.md</c> §3.4). So this method
    /// asks <see cref="IRandomSource"/> for the nonce and nothing else — the one method of the four that
    /// draws no key material of its own.
    /// </para>
    /// <para>
    /// The encapsulation comes before the header is built, and therefore before anything is written: a public
    /// key Enigma.Core cannot use leaves the output stream untouched.
    /// </para>
    /// </remarks>
    private async Task EncryptCoreAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] publicKey,
        MLKemParameterSet parameterSet,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] nonce = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.NonceSizeBytes);

        byte[]? dataKey = null;
        try
        {
            byte[] encapsulation;
            (encapsulation, dataKey) = Encapsulate(publicKey, parameterSet);

            byte[] header = await HeaderWriter.WriteMLKemHeaderAsync(
                output,
                cipher,
                parameterSet,
                nonce,
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
            CryptoHelpers.Clear(dataKey);
        }
    }

    /// <summary>
    /// The decrypt half of the canonical order (<c>docs/format.md</c> §7.2): parse and bound the header,
    /// decapsulate, confirm the key, then — and only then — touch the payload.
    /// </summary>
    /// <remarks>
    /// <b>This is the method the key-confirmation tag exists for.</b> FIPS 203 implicit rejection means
    /// decapsulating with a well-formed but wrong private key <i>succeeds</i>, returning a different 32-byte
    /// secret — so the tag is the only thing standing between a wrong key and streaming the whole payload
    /// before the GCM tag finally disagrees (§6.3).
    /// </remarks>
    private async Task DecryptCoreAsync(
        Stream input,
        Stream output,
        byte[] privateKey,
        DataEncryptionLimits? limits,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            input,
            EncryptionMethod.MLKem,
            limits ?? DataEncryptionLimits.Default,
            cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        // Both are non-null for method 0x04: HeaderReader populates them — the parameter set from offset 5,
        // the encapsulation bounded by MaxEncapsulationLength — or throws.
        byte[] encapsulation = parsed.Encapsulation!;
        MLKemParameterSet parameterSet = parsed.MLKemParameterSet!.Value;

        byte[]? dataKey = null;
        try
        {
            dataKey = Decapsulate(encapsulation, privateKey, parameterSet);

            if (!KeyConfirmation.Verify(
                    _hmacServiceFactory.CreateHmacSha256Service(),
                    dataKey,
                    parsed.BytesBeforeTag,
                    parsed.KeyConfirmationTag))
            {
                throw new DataDecryptionException(
                    "The ML-KEM private key is wrong: the container's key-confirmation tag does not match the decapsulated shared secret. FIPS 203 implicit rejection means decapsulation itself could not report this. No payload byte was read.");
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
    /// Encapsulates a fresh shared secret against the recipient's public key, translating an encapsulation
    /// failure into the argument error it can only be.
    /// </summary>
    /// <param name="publicKey">The recipient's raw FIPS 203 encapsulation key.</param>
    /// <param name="parameterSet">The parameter set to encapsulate under.</param>
    /// <returns>The encapsulation to write into the header, and the 32-byte shared secret to use as the data key.</returns>
    /// <exception cref="ArgumentException"><paramref name="publicKey"/> is malformed or is not a key for <paramref name="parameterSet"/>.</exception>
    /// <remarks>
    /// <see cref="IMLKemService.Encapsulate"/> takes the public key and nothing else, so the only thing a
    /// failure can be about is the public key the caller supplied — which makes
    /// <see cref="ArgumentException"/> the honest translation of Enigma.Core's
    /// <see cref="CryptographicException"/>, and matches what its own RSA path already reports for an
    /// unusable public key. The decrypt side is deliberately <i>not</i> symmetrical: there, the same
    /// exception could equally mean the container's parameter-set byte was edited, so it stays a
    /// <see cref="DataDecryptionException"/> (see <see cref="Decapsulate"/>).
    /// </remarks>
    private (byte[] Encapsulation, byte[] SharedSecret) Encapsulate(
        byte[] publicKey,
        MLKemParameterSet parameterSet)
    {
        try
        {
            return _mlKemServiceFactory.CreateMLKemService(parameterSet).Encapsulate(publicKey);
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException(
                $"The ML-KEM public key could not be used to encapsulate a shared secret. It is malformed, or it is not a {parameterSet} key.",
                nameof(publicKey),
                exception);
        }
    }

    /// <summary>
    /// Recovers the shared secret from the header's encapsulation, translating a decapsulation failure.
    /// </summary>
    /// <param name="encapsulation">The encapsulation read from the header.</param>
    /// <param name="privateKey">The recipient's raw FIPS 203 decapsulation key.</param>
    /// <param name="parameterSet">The parameter set recorded at header offset 5.</param>
    /// <returns>The 32-byte shared secret — the data key.</returns>
    /// <exception cref="DataDecryptionException">The private key and the container's encapsulation cannot be combined.</exception>
    /// <remarks>
    /// <para>
    /// <b>Every decapsulation failure becomes a decryption error, including a private key of the wrong
    /// length.</b> Enigma.Core raises one <see cref="CryptographicException"/> whose own message names three
    /// causes at once — a malformed ciphertext, a malformed private key, or either being for a different
    /// parameter set — so they cannot be told apart without matching on message text. That matters here
    /// because two of those causes point in opposite directions: a wrong-length key is the caller's, while an
    /// edited parameter-set byte is the container's. Reporting an argument error for a tampered file would be
    /// worse than reporting a decryption error for a mis-supplied key, so both are wrapped, with the original
    /// kept as <see cref="Exception.InnerException"/> where the specific cause stays readable
    /// (<c>docs/format.md</c> §9). This is the same resolution the RSA service reached for OAEP.
    /// </para>
    /// <para>
    /// There is no length check on the result, unlike the RSA service's: FIPS 203 fixes the shared-secret
    /// length at 32 bytes independently of the ciphertext, so no sender — hostile or otherwise — can
    /// influence it. The RSA guard exists because a sender holding the recipient's public key chooses what
    /// gets wrapped; encapsulation offers no such freedom.
    /// </para>
    /// </remarks>
    private byte[] Decapsulate(byte[] encapsulation, byte[] privateKey, MLKemParameterSet parameterSet)
    {
        try
        {
            return _mlKemServiceFactory.CreateMLKemService(parameterSet).Decapsulate(encapsulation, privateKey);
        }
        catch (CryptographicException exception)
        {
            throw new DataDecryptionException(
                $"The ML-KEM private key does not open this container: the shared secret could not be decapsulated. The key may be malformed, or it may not be a {parameterSet} key — which is what the container's parameter-set byte claims it was encapsulated under.",
                exception);
        }
    }

    private static void ValidateKey(byte[] key, string paramName)
    {
        if (key is null) throw new ArgumentNullException(paramName);

        if (key.Length == 0)
        {
            throw new ArgumentException("The ML-KEM key must not be empty.", paramName);
        }
    }
}
