using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// One uniform surface over <see cref="Pbkdf2DataEncryptionService"/> and
/// <see cref="Argon2DataEncryptionService"/>, so every property that is supposed to hold for both
/// methods is asserted for both instead of once for whichever service the test happened to pick.
/// </summary>
/// <remarks>
/// <para>
/// The cost parameters are fixed here, and deliberately far below the production defaults: 1,000 PBKDF2
/// iterations and a 1 MiB single-lane Argon2 instead of 600,000 iterations and 64 MiB. The suites below
/// assert format and behaviour, neither of which depends on the work factor, and the default costs are
/// pinned separately by the golden vectors and <c>FormatConstantsTests</c>.
/// </para>
/// <para>
/// The cost <b>fields</b>, on the other hand, are exposed (<see cref="CostFields"/>) so the limit sweep
/// can be generated rather than hand-written.
/// </para>
/// </remarks>
internal abstract class PasswordServiceAdapter
{
    /// <summary>The PBKDF2 iteration count every adapter-driven container is written with.</summary>
    internal const int TestIterations = 1_000;

    /// <summary>The Argon2 pass count every adapter-driven container is written with.</summary>
    internal const int TestArgon2Iterations = 1;

    /// <summary>The Argon2 memory cost, in KiB, every adapter-driven container is written with.</summary>
    internal const int TestArgon2MemorySizeKb = 1_024;

    /// <summary>The Argon2 lane count every adapter-driven container is written with.</summary>
    internal const int TestArgon2DegreeOfParallelism = 1;

    /// <summary>The method byte this adapter's service reads and writes.</summary>
    internal abstract EncryptionMethod Method { get; }

    /// <summary>The header length of this method, in bytes — 53 or 61.</summary>
    internal abstract int HeaderLength { get; }

    /// <summary>
    /// The header's cost fields: the name, the absolute offset of the little-endian <c>Int32</c>, and the
    /// cap <see cref="DataEncryptionLimits.Default"/> applies to it.
    /// </summary>
    internal abstract IReadOnlyList<CostField> CostFields { get; }

    /// <summary>Builds an adapter over a service wired for a test.</summary>
    /// <param name="method">Which of the two methods to drive.</param>
    /// <param name="randomSource">
    /// The salt/nonce source. Pass <see langword="null"/> for the real one, or a fixed source to make the
    /// written container reproducible.
    /// </param>
    /// <param name="poisonKdf">
    /// When <see langword="true"/>, the key-derivation factory throws <see cref="KdfInvokedException"/>
    /// on use — which is how the limit tests prove no derivation work was attempted.
    /// </param>
    /// <returns>The adapter.</returns>
    internal static PasswordServiceAdapter Create(
        PasswordMethod method,
        IRandomSource? randomSource = null,
        bool poisonKdf = false) => method switch
    {
        PasswordMethod.Pbkdf2 => new Pbkdf2Adapter(randomSource ?? new RandomSource(), poisonKdf),
        _ => new Argon2Adapter(randomSource ?? new RandomSource(), poisonKdf),
    };

    /// <summary>Encrypts with a password supplied as bytes.</summary>
    /// <param name="input">The plaintext stream.</param>
    /// <param name="output">The container stream.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="password">The password bytes.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] password,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Encrypts with a password supplied as characters.</summary>
    /// <param name="input">The plaintext stream.</param>
    /// <param name="output">The container stream.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="password">The password characters.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        char[] password,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Decrypts with a password supplied as bytes.</summary>
    /// <param name="input">The container stream.</param>
    /// <param name="output">The plaintext stream.</param>
    /// <param name="password">The password bytes.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Decrypts with a password supplied as characters.</summary>
    /// <param name="input">The container stream.</param>
    /// <param name="output">The plaintext stream.</param>
    /// <param name="password">The password characters.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task DecryptAsync(
        Stream input,
        Stream output,
        char[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>A cost field of a header: where it sits and what bounds it.</summary>
    /// <param name="Name">The field's name, for test output.</param>
    /// <param name="Offset">The absolute offset of the 4-byte little-endian value.</param>
    /// <param name="Cap">The largest value <see cref="DataEncryptionLimits.Default"/> accepts.</param>
    internal sealed record CostField(string Name, int Offset, int Cap);

    private sealed class Pbkdf2Adapter : PasswordServiceAdapter
    {
        private readonly Pbkdf2DataEncryptionService _service;

        internal Pbkdf2Adapter(IRandomSource randomSource, bool poisonKdf) =>
            _service = new Pbkdf2DataEncryptionService(
                new BlockCipherServiceFactory(),
                poisonKdf ? new PoisonedPbkdf2ServiceFactory() : new Pbkdf2ServiceFactory(),
                new HmacServiceFactory(),
                randomSource);

        internal override EncryptionMethod Method => EncryptionMethod.Pbkdf2;

        internal override int HeaderLength => 53;

        internal override IReadOnlyList<CostField> CostFields =>
        [
            new("PBKDF2 iteration count", 33, DataEncryptionLimits.Default.MaxPbkdf2Iterations),
        ];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            byte[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(input, output, cipher, password, TestIterations, progress, cancellationToken);

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            char[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(input, output, cipher, password, TestIterations, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            byte[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            char[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);
    }

    private sealed class Argon2Adapter : PasswordServiceAdapter
    {
        private readonly Argon2DataEncryptionService _service;

        internal Argon2Adapter(IRandomSource randomSource, bool poisonKdf) =>
            _service = new Argon2DataEncryptionService(
                new BlockCipherServiceFactory(),
                poisonKdf ? new PoisonedArgon2ServiceFactory() : new Argon2ServiceFactory(),
                new HmacServiceFactory(),
                randomSource);

        internal override EncryptionMethod Method => EncryptionMethod.Argon2;

        internal override int HeaderLength => 61;

        internal override IReadOnlyList<CostField> CostFields =>
        [
            new("Argon2 iteration count", 33, DataEncryptionLimits.Default.MaxArgon2Iterations),
            new("Argon2 degree of parallelism", 37, DataEncryptionLimits.Default.MaxArgon2DegreeOfParallelism),
            new("Argon2 memory size in KiB", 41, DataEncryptionLimits.Default.MaxArgon2MemorySizeKb),
        ];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            byte[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input,
                output,
                cipher,
                password,
                TestArgon2Iterations,
                TestArgon2MemorySizeKb,
                TestArgon2DegreeOfParallelism,
                progress,
                cancellationToken);

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            char[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input,
                output,
                cipher,
                password,
                TestArgon2Iterations,
                TestArgon2MemorySizeKb,
                TestArgon2DegreeOfParallelism,
                progress,
                cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            byte[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            char[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);
    }
}
