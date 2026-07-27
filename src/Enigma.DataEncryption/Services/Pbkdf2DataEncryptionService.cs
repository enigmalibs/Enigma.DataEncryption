using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption;

/// <summary>
/// The default <see cref="IPbkdf2DataEncryptionService"/>, implementing container method <c>0x01</c>
/// on top of Enigma.Core's PBKDF2, HMAC and block-cipher services.
/// </summary>
/// <remarks>
/// Stateless and safe for concurrent use; registered as a singleton by
/// <see cref="Microsoft.Extensions.DependencyInjection.ServiceCollectionExtensions.AddEnigmaDataEncryption"/>.
/// </remarks>
public sealed class Pbkdf2DataEncryptionService : IPbkdf2DataEncryptionService
{
    private readonly IBlockCipherServiceFactory _blockCipherServiceFactory;
    private readonly IPbkdf2ServiceFactory _pbkdf2ServiceFactory;
    private readonly IHmacServiceFactory _hmacServiceFactory;
    private readonly IRandomSource _randomSource;

    /// <summary>
    /// Initializes a new instance backed by Enigma.Core's default factories, for use without a
    /// dependency-injection container.
    /// </summary>
    public Pbkdf2DataEncryptionService()
        : this(new BlockCipherServiceFactory(), new Pbkdf2ServiceFactory(), new HmacServiceFactory())
    {
    }

    /// <summary>
    /// Initializes a new instance with caller-supplied Enigma.Core factories. This is the constructor
    /// a dependency-injection container resolves.
    /// </summary>
    /// <param name="blockCipherServiceFactory">Supplies the AEAD block cipher selected by the container's cipher byte.</param>
    /// <param name="pbkdf2ServiceFactory">Supplies the PBKDF2 key-derivation service.</param>
    /// <param name="hmacServiceFactory">Supplies the HMAC-SHA256 service backing key confirmation.</param>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    public Pbkdf2DataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IPbkdf2ServiceFactory pbkdf2ServiceFactory,
        IHmacServiceFactory hmacServiceFactory)
        : this(blockCipherServiceFactory, pbkdf2ServiceFactory, hmacServiceFactory, new RandomSource())
    {
    }

    // Test seam: lets the golden-vector suite pin the encrypt path byte-for-byte by supplying
    // deterministic salt and nonce bytes. Internal by design — see IRandomSource.
    internal Pbkdf2DataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IPbkdf2ServiceFactory pbkdf2ServiceFactory,
        IHmacServiceFactory hmacServiceFactory,
        IRandomSource randomSource)
    {
        _blockCipherServiceFactory = blockCipherServiceFactory ?? throw new ArgumentNullException(nameof(blockCipherServiceFactory));
        _pbkdf2ServiceFactory = pbkdf2ServiceFactory ?? throw new ArgumentNullException(nameof(pbkdf2ServiceFactory));
        _hmacServiceFactory = hmacServiceFactory ?? throw new ArgumentNullException(nameof(hmacServiceFactory));
        _randomSource = randomSource ?? throw new ArgumentNullException(nameof(randomSource));
    }

    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Validation is synchronous — an argument mistake faults the call, not the returned task — and
        // runs in declaration order, so the first parameter at fault is the one reported.
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        PasswordCredential.Validate(password, nameof(password));
        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(iterations), iterations, "The PBKDF2 iteration count must be greater than zero.");
        }

        return EncryptCoreAsync(input, output, cipher, password, iterations, progress, cancellationToken);
    }

    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        char[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        PasswordCredential.Validate(password, nameof(password));

        return EncryptWithEncodedPasswordAsync(
            input, output, cipher, password, iterations, progress, cancellationToken);
    }

    /// <inheritdoc />
    public Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        PasswordCredential.Validate(password, nameof(password));

        return DecryptCoreAsync(input, output, password, limits, progress, cancellationToken);
    }

    /// <inheritdoc />
    public Task DecryptAsync(
        Stream input,
        Stream output,
        char[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        PasswordCredential.Validate(password, nameof(password));

        return DecryptWithEncodedPasswordAsync(input, output, password, limits, progress, cancellationToken);
    }

    /// <summary>
    /// The encrypt half of the canonical order (<c>docs/format.md</c> §7.1): salt and nonce, derive,
    /// header, tag, write, payload — with the data key cleared in a <c>finally</c> that encloses every
    /// use of it.
    /// </summary>
    private async Task EncryptCoreAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] password,
        int iterations,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        // Checked before the derivation, not after: a cancelled call must not spend 600,000 iterations
        // before noticing.
        cancellationToken.ThrowIfCancellationRequested();

        byte[] salt = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.SaltSizeBytes);
        byte[] nonce = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.NonceSizeBytes);

        byte[]? dataKey = null;
        try
        {
            dataKey = DeriveKey(password, salt, iterations);

            byte[] header = await HeaderWriter.WritePbkdf2HeaderAsync(
                output,
                cipher,
                nonce,
                salt,
                iterations,
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
    /// The decrypt half of the canonical order (<c>docs/format.md</c> §7.2): parse and bound the
    /// header, re-derive, confirm the key, then — and only then — touch the payload.
    /// </summary>
    private async Task DecryptCoreAsync(
        Stream input,
        Stream output,
        byte[] password,
        DataEncryptionLimits? limits,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ParsedHeader parsed = await HeaderReader.ReadAsync(
            input,
            EncryptionMethod.Pbkdf2,
            limits ?? DataEncryptionLimits.Default,
            cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        // Both are non-null for method 0x01: HeaderReader populates them or throws.
        byte[] salt = parsed.Salt!;
        int iterations = parsed.Header.Pbkdf2Iterations!.Value;

        byte[]? dataKey = null;
        try
        {
            dataKey = DeriveKey(password, salt, iterations);

            if (!KeyConfirmation.Verify(
                    _hmacServiceFactory.CreateHmacSha256Service(),
                    dataKey,
                    parsed.BytesBeforeTag,
                    parsed.KeyConfirmationTag))
            {
                throw new DataDecryptionException(
                    "The password is wrong: the container's key-confirmation tag does not match the derived key. No payload byte was read.");
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

    private async Task EncryptWithEncodedPasswordAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        char[] password,
        int iterations,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        byte[]? passwordBytes = null;
        try
        {
            passwordBytes = PasswordCredential.Encode(password);
            await EncryptAsync(input, output, cipher, passwordBytes, iterations, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptoHelpers.Clear(passwordBytes);
        }
    }

    private async Task DecryptWithEncodedPasswordAsync(
        Stream input,
        Stream output,
        char[] password,
        DataEncryptionLimits? limits,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        byte[]? passwordBytes = null;
        try
        {
            passwordBytes = PasswordCredential.Encode(password);
            await DecryptAsync(input, output, passwordBytes, limits, progress, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptoHelpers.Clear(passwordBytes);
        }
    }

    private byte[] DeriveKey(byte[] password, byte[] salt, int iterations) =>
        _pbkdf2ServiceFactory.CreatePbkdf2Service().DeriveKey(
            password,
            salt,
            iterations,
            keySizeBytes: DataEncryptionDefaults.DataKeySizeBytes,
            prf: Pbkdf2Prf.HmacSha256);
}
