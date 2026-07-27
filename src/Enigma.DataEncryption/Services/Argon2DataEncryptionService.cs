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
/// The default <see cref="IArgon2DataEncryptionService"/>, implementing container method <c>0x02</c>
/// on top of Enigma.Core's Argon2, HMAC and block-cipher services.
/// </summary>
/// <remarks>
/// Stateless and safe for concurrent use; registered as a singleton by
/// <see cref="Microsoft.Extensions.DependencyInjection.ServiceCollectionExtensions.AddEnigmaDataEncryption"/>.
/// </remarks>
public sealed class Argon2DataEncryptionService : IArgon2DataEncryptionService
{
    private readonly IBlockCipherServiceFactory _blockCipherServiceFactory;
    private readonly IArgon2ServiceFactory _argon2ServiceFactory;
    private readonly IHmacServiceFactory _hmacServiceFactory;
    private readonly IRandomSource _randomSource;

    /// <summary>
    /// Initializes a new instance backed by Enigma.Core's default factories, for use without a
    /// dependency-injection container.
    /// </summary>
    public Argon2DataEncryptionService()
        : this(new BlockCipherServiceFactory(), new Argon2ServiceFactory(), new HmacServiceFactory())
    {
    }

    /// <summary>
    /// Initializes a new instance with caller-supplied Enigma.Core factories. This is the constructor
    /// a dependency-injection container resolves.
    /// </summary>
    /// <param name="blockCipherServiceFactory">Supplies the AEAD block cipher selected by the container's cipher byte.</param>
    /// <param name="argon2ServiceFactory">Supplies the Argon2id key-derivation service.</param>
    /// <param name="hmacServiceFactory">Supplies the HMAC-SHA256 service backing key confirmation.</param>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    public Argon2DataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IArgon2ServiceFactory argon2ServiceFactory,
        IHmacServiceFactory hmacServiceFactory)
        : this(blockCipherServiceFactory, argon2ServiceFactory, hmacServiceFactory, new RandomSource())
    {
    }

    // Test seam: lets the golden-vector suite pin the encrypt path byte-for-byte by supplying
    // deterministic salt and nonce bytes. Internal by design — see IRandomSource.
    internal Argon2DataEncryptionService(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        IArgon2ServiceFactory argon2ServiceFactory,
        IHmacServiceFactory hmacServiceFactory,
        IRandomSource randomSource)
    {
        _blockCipherServiceFactory = blockCipherServiceFactory ?? throw new ArgumentNullException(nameof(blockCipherServiceFactory));
        _argon2ServiceFactory = argon2ServiceFactory ?? throw new ArgumentNullException(nameof(argon2ServiceFactory));
        _hmacServiceFactory = hmacServiceFactory ?? throw new ArgumentNullException(nameof(hmacServiceFactory));
        _randomSource = randomSource ?? throw new ArgumentNullException(nameof(randomSource));
    }

    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] password,
        int iterations = DataEncryptionDefaults.Argon2Iterations,
        int memorySizeKb = DataEncryptionDefaults.Argon2MemorySizeKb,
        int degreeOfParallelism = DataEncryptionDefaults.Argon2DegreeOfParallelism,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Validation is synchronous — an argument mistake faults the call, not the returned task — and
        // runs in declaration order, so the first parameter at fault is the one reported.
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        PasswordCredential.Validate(password, nameof(password));
        RequirePositive(iterations, nameof(iterations), "The Argon2 iteration count");
        RequirePositive(memorySizeKb, nameof(memorySizeKb), "The Argon2 memory size in KiB");
        RequirePositive(degreeOfParallelism, nameof(degreeOfParallelism), "The Argon2 degree of parallelism");

        return EncryptCoreAsync(
            input, output, cipher, password, iterations, memorySizeKb, degreeOfParallelism, progress, cancellationToken);
    }

    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        char[] password,
        int iterations = DataEncryptionDefaults.Argon2Iterations,
        int memorySizeKb = DataEncryptionDefaults.Argon2MemorySizeKb,
        int degreeOfParallelism = DataEncryptionDefaults.Argon2DegreeOfParallelism,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        PasswordCredential.Validate(password, nameof(password));

        return EncryptWithEncodedPasswordAsync(
            input, output, cipher, password, iterations, memorySizeKb, degreeOfParallelism, progress, cancellationToken);
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
        int memorySizeKb,
        int degreeOfParallelism,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        // Checked before the derivation, not after: a cancelled call must not spend 64 MiB and three
        // passes over it before noticing.
        cancellationToken.ThrowIfCancellationRequested();

        byte[] salt = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.SaltSizeBytes);
        byte[] nonce = _randomSource.GenerateRandomBytes(DataEncryptionDefaults.NonceSizeBytes);

        byte[]? dataKey = null;
        try
        {
            dataKey = DeriveKey(password, salt, iterations, memorySizeKb, degreeOfParallelism);

            byte[] header = await HeaderWriter.WriteArgon2HeaderAsync(
                output,
                cipher,
                nonce,
                salt,
                iterations,
                degreeOfParallelism,
                memorySizeKb,
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
    /// <remarks>
    /// The bounds come first for a reason: <see cref="HeaderReader"/> has already rejected a header
    /// claiming a gigabyte of memory or two billion passes, so nothing below can be talked into
    /// allocating it.
    /// </remarks>
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
            EncryptionMethod.Argon2,
            limits ?? DataEncryptionLimits.Default,
            cancellationToken).ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        // All four are non-null for method 0x02: HeaderReader populates them or throws.
        byte[] salt = parsed.Salt!;
        int iterations = parsed.Header.Argon2Iterations!.Value;
        int memorySizeKb = parsed.Header.Argon2MemorySizeKb!.Value;
        int degreeOfParallelism = parsed.Header.Argon2DegreeOfParallelism!.Value;

        byte[]? dataKey = null;
        try
        {
            dataKey = DeriveKey(password, salt, iterations, memorySizeKb, degreeOfParallelism);

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
        int memorySizeKb,
        int degreeOfParallelism,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        byte[]? passwordBytes = null;
        try
        {
            passwordBytes = PasswordCredential.Encode(password);
            await EncryptAsync(
                input, output, cipher, passwordBytes, iterations, memorySizeKb, degreeOfParallelism, progress, cancellationToken)
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

    /// <remarks>
    /// The arguments are named at the call site deliberately: Enigma.Core's parameter order is
    /// <c>(iterations, memorySizeKb, degreeOfParallelism)</c> while the header's field order is
    /// <c>(iterations, degreeOfParallelism, memorySizeKb)</c> — see <c>docs/format.md</c> §3.2. Naming
    /// them makes a silent transposition between the two impossible to write.
    /// </remarks>
    private byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        int iterations,
        int memorySizeKb,
        int degreeOfParallelism) =>
        _argon2ServiceFactory.CreateArgon2Service().DeriveKey(
            password,
            salt,
            iterations: iterations,
            memorySizeKb: memorySizeKb,
            degreeOfParallelism: degreeOfParallelism,
            keySizeBytes: DataEncryptionDefaults.DataKeySizeBytes,
            variant: Argon2Variant.Argon2id,
            version: Argon2Version.Version13);

    private static void RequirePositive(int value, string paramName, string description)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(paramName, value, $"{description} must be greater than zero.");
        }
    }
}
