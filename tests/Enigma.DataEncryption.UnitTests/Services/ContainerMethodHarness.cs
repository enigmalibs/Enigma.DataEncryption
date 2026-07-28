using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// One uniform surface over all five encryption methods — streams, file paths and a wrong credential —
/// so the cross-cutting suites can be written once and generated over every method.
/// </summary>
/// <remarks>
/// <para>
/// PHASE02–PHASE04 each brought their own adapter or static helper, shaped around the arguments that
/// method actually takes. This one goes the other way: it hides every difference between the four, which
/// is exactly what a suite asserting "no container makes the library throw the wrong kind of exception"
/// or "one instance is safe to drive concurrently" needs. Where a suite <i>does</i> care about a method's
/// own arguments, the per-method helpers remain the right tool.
/// </para>
/// <para>
/// <b>The credentials are committed fixtures, not generated key material.</b> RSA key generation costs
/// seconds and ML-KEM generation is not free either; the sweep below builds thousands of cases from a
/// handful of containers, so the credential has to be cheap and — more importantly — identical from run
/// to run. <see cref="RsaKeyFixture"/> and <see cref="MLKemKeyFixture"/> stay the right choice for the
/// per-method suites, where freshness is the point.
/// </para>
/// <para>
/// The KDF costs are the low test values, for the reason <see cref="PasswordServiceAdapter"/> gives: the
/// properties asserted here do not depend on the work factor, and the production defaults are pinned by
/// the golden vectors instead.
/// </para>
/// </remarks>
internal abstract class ContainerMethodHarness
{
    /// <summary>The PBKDF2 iteration count every harness-written container uses.</summary>
    internal const int Pbkdf2Iterations = 1_000;

    /// <summary>The Argon2 pass count every harness-written container uses.</summary>
    internal const int Argon2Iterations = 1;

    /// <summary>The Argon2 memory cost, in KiB, every harness-written container uses.</summary>
    internal const int Argon2MemorySizeKb = 1_024;

    /// <summary>The Argon2 lane count every harness-written container uses.</summary>
    internal const int Argon2DegreeOfParallelism = 1;

    /// <summary>The ML-KEM parameter set the harness encapsulates under — the smallest, so the containers are too.</summary>
    internal const MLKemParameterSet KemParameterSet = MLKemParameterSet.MLKem512;

    /// <summary>All five methods, for the theories that sweep them.</summary>
    internal static ContainerMethodKind[] All =>
    [
        ContainerMethodKind.Pbkdf2, ContainerMethodKind.Argon2, ContainerMethodKind.Rsa,
        ContainerMethodKind.MLKem, ContainerMethodKind.Hybrid,
    ];

    /// <summary>
    /// The methods whose header carries an ML-KEM parameter-set byte at offset 5, for the sweeps that
    /// corrupt it.
    /// </summary>
    internal static ContainerMethodKind[] WithParameterSetByte =>
        [ContainerMethodKind.MLKem, ContainerMethodKind.Hybrid];

    /// <summary>All four ciphers, for the theories that sweep them.</summary>
    internal static Cipher[] AllCiphers =>
        [Cipher.Aes256Gcm, Cipher.Twofish256Gcm, Cipher.Serpent256Gcm, Cipher.Camellia256Gcm];

    /// <summary>The method this harness drives.</summary>
    internal abstract ContainerMethodKind Kind { get; }

    /// <summary>The method byte its containers carry.</summary>
    internal abstract EncryptionMethod Method { get; }

    /// <summary>
    /// The header length of the containers this harness writes — fixed, because the credential is.
    /// </summary>
    internal abstract int HeaderLength { get; }

    /// <summary>
    /// The header's little-endian <c>Int32</c> cost and length fields: the name, the absolute offset, and
    /// the cap <see cref="DataEncryptionLimits.Default"/> applies.
    /// </summary>
    internal abstract IReadOnlyList<Int32HeaderField> Int32Fields { get; }

    /// <summary>Builds a harness for a method.</summary>
    /// <param name="kind">Which method to drive.</param>
    /// <returns>The harness.</returns>
    internal static ContainerMethodHarness For(ContainerMethodKind kind) => kind switch
    {
        ContainerMethodKind.Pbkdf2 => new Pbkdf2Harness(),
        ContainerMethodKind.Argon2 => new Argon2Harness(),
        ContainerMethodKind.Rsa => new RsaHarness(),
        ContainerMethodKind.Hybrid => new HybridHarness(),
        _ => new MLKemHarness(),
    };

    /// <summary>
    /// The header length a method's harness produces, without building one — theory data has to be
    /// enumerated synchronously at discovery time.
    /// </summary>
    /// <param name="kind">The method.</param>
    /// <returns>53, 61, 293, 806 or 1,066.</returns>
    internal static int HeaderLengthOf(ContainerMethodKind kind) => kind switch
    {
        ContainerMethodKind.Pbkdf2 => FormatLayout.Pbkdf2HeaderLength,
        ContainerMethodKind.Argon2 => FormatLayout.Argon2HeaderLength,
        ContainerMethodKind.Rsa => RsaTestData.HeaderLength2048,
        ContainerMethodKind.Hybrid => HybridTestData.HeaderLengthOf(KemParameterSet),
        _ => MLKemTestData.HeaderLengthOf(KemParameterSet),
    };

    /// <summary>The wire byte a method's containers carry at offset 2.</summary>
    /// <param name="kind">The method.</param>
    /// <returns>The method byte.</returns>
    internal static byte MethodByteOf(ContainerMethodKind kind) => kind switch
    {
        ContainerMethodKind.Pbkdf2 => (byte)EncryptionMethod.Pbkdf2,
        ContainerMethodKind.Argon2 => (byte)EncryptionMethod.Argon2,
        ContainerMethodKind.Rsa => (byte)EncryptionMethod.Rsa,
        ContainerMethodKind.Hybrid => (byte)EncryptionMethod.Hybrid,
        _ => (byte)EncryptionMethod.MLKem,
    };

    /// <summary>Encrypts a stream into a container.</summary>
    /// <param name="input">The plaintext stream.</param>
    /// <param name="output">The container stream.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher = Cipher.Aes256Gcm,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Decrypts a container with the right credential.</summary>
    /// <param name="input">The container stream.</param>
    /// <param name="output">The plaintext stream.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task DecryptAsync(
        Stream input,
        Stream output,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a container with a credential that cannot open it.
    /// </summary>
    /// <param name="input">The container stream.</param>
    /// <param name="output">The plaintext stream.</param>
    /// <returns>A task representing the operation.</returns>
    /// <remarks>
    /// What "wrong" means differs by method, and each is the natural wrong credential for it: a
    /// one-bit-different password for PBKDF2 and Argon2; the committed encrypted private-key PEM opened
    /// with the wrong passphrase for RSA (which <c>docs/format.md</c> §9 maps to
    /// <see cref="DataDecryptionException"/> alongside a wrong key, because Enigma.Core reports them
    /// identically); and a freshly generated, unrelated key pair for ML-KEM — the case FIPS 203 implicit
    /// rejection lets <i>succeed</i> at decapsulation, so only the key-confirmation tag catches it.
    /// <para>
    /// For the hybrid it is the <b>right RSA key and a wrong ML-KEM key</b>. That is the pointed choice of
    /// the two available: the RSA half unwraps cleanly, decapsulation succeeds under implicit rejection,
    /// and the container is nevertheless refused — so the failure can only have come from the combined key
    /// the confirmation tag covers.
    /// </para>
    /// </remarks>
    internal abstract Task DecryptWithWrongCredentialAsync(Stream input, Stream output);

    /// <summary>Encrypts one file to another through the file-path extension methods.</summary>
    /// <param name="inputPath">The plaintext file.</param>
    /// <param name="outputPath">The container file.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task EncryptFileAsync(
        string inputPath,
        string outputPath,
        Cipher cipher = Cipher.Aes256Gcm,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Decrypts one file to another through the file-path extension methods.</summary>
    /// <param name="inputPath">The container file.</param>
    /// <param name="outputPath">The plaintext file.</param>
    /// <param name="progress">Optional progress receiver.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task DecryptFileAsync(
        string inputPath,
        string outputPath,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Decrypts a file with a credential that cannot open it.</summary>
    /// <param name="inputPath">The container file.</param>
    /// <param name="outputPath">The plaintext file that must not survive.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task DecryptFileWithWrongCredentialAsync(string inputPath, string outputPath);

    /// <summary>
    /// Invokes the file-path <c>DecryptFileAsync</c> with an empty credential, to show that a rejected
    /// argument never reaches the filesystem.
    /// </summary>
    /// <param name="inputPath">The container file.</param>
    /// <param name="outputPath">The output path that must not be created or truncated.</param>
    /// <returns>A task representing the operation.</returns>
    internal abstract Task DecryptFileWithEmptyCredentialAsync(string inputPath, string outputPath);

    /// <summary>Encrypts a plaintext and returns the complete container.</summary>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <returns>The container bytes.</returns>
    internal async Task<byte[]> EncryptToBytesAsync(byte[] plaintext, Cipher cipher = Cipher.Aes256Gcm)
    {
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await EncryptAsync(input, output, cipher).ConfigureAwait(false);
        return output.ToArray();
    }

    /// <summary>Decrypts a container and returns the recovered plaintext.</summary>
    /// <param name="container">The container bytes.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <returns>The recovered plaintext.</returns>
    internal async Task<byte[]> DecryptToBytesAsync(byte[] container, DataEncryptionLimits? limits = null)
    {
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();
        await DecryptAsync(input, output, limits).ConfigureAwait(false);
        return output.ToArray();
    }

    /// <summary>Decrypts a container with the wrong credential and returns whatever came out.</summary>
    /// <param name="container">The container bytes.</param>
    /// <returns>The recovered plaintext, if the call somehow succeeds.</returns>
    internal async Task<byte[]> DecryptWithWrongCredentialToBytesAsync(byte[] container)
    {
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();
        await DecryptWithWrongCredentialAsync(input, output).ConfigureAwait(false);
        return output.ToArray();
    }

    /// <summary>An <c>Int32</c> header field: where it sits and what bounds it.</summary>
    /// <param name="Name">The field's name, for test output.</param>
    /// <param name="Offset">The absolute offset of the 4-byte little-endian value.</param>
    /// <param name="Cap">The largest value <see cref="DataEncryptionLimits.Default"/> accepts.</param>
    internal sealed record Int32HeaderField(string Name, int Offset, int Cap);

    private sealed class Pbkdf2Harness : ContainerMethodHarness
    {
        private readonly IPbkdf2DataEncryptionService _service = new Pbkdf2DataEncryptionService(
            new BlockCipherServiceFactory(), new Pbkdf2ServiceFactory(), new HmacServiceFactory());

        internal override ContainerMethodKind Kind => ContainerMethodKind.Pbkdf2;

        internal override EncryptionMethod Method => EncryptionMethod.Pbkdf2;

        internal override int HeaderLength => FormatLayout.Pbkdf2HeaderLength;

        internal override IReadOnlyList<Int32HeaderField> Int32Fields =>
        [
            new("PBKDF2 iteration count", 33, DataEncryptionLimits.Default.MaxPbkdf2Iterations),
        ];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input, output, cipher, PasswordTestData.PasswordBytes(), Pbkdf2Iterations, progress,
                cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(
                input, output, PasswordTestData.PasswordBytes(), limits, progress, cancellationToken);

        internal override Task DecryptWithWrongCredentialAsync(Stream input, Stream output) =>
            _service.DecryptAsync(input, output, PasswordTestData.WrongPasswordBytes(), null, null, CancellationToken.None);

        internal override Task EncryptFileAsync(
            string inputPath,
            string outputPath,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptFileAsync(
                inputPath, outputPath, cipher, PasswordTestData.PasswordBytes(), Pbkdf2Iterations, progress,
                cancellationToken);

        internal override Task DecryptFileAsync(
            string inputPath,
            string outputPath,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, PasswordTestData.PasswordBytes(), null, progress, cancellationToken);

        internal override Task DecryptFileWithWrongCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(inputPath, outputPath, PasswordTestData.WrongPasswordBytes());

        internal override Task DecryptFileWithEmptyCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(inputPath, outputPath, Array.Empty<byte>());
    }

    private sealed class Argon2Harness : ContainerMethodHarness
    {
        private readonly IArgon2DataEncryptionService _service = new Argon2DataEncryptionService(
            new BlockCipherServiceFactory(), new Argon2ServiceFactory(), new HmacServiceFactory());

        internal override ContainerMethodKind Kind => ContainerMethodKind.Argon2;

        internal override EncryptionMethod Method => EncryptionMethod.Argon2;

        internal override int HeaderLength => FormatLayout.Argon2HeaderLength;

        internal override IReadOnlyList<Int32HeaderField> Int32Fields =>
        [
            new("Argon2 iteration count", 33, DataEncryptionLimits.Default.MaxArgon2Iterations),
            new("Argon2 degree of parallelism", 37, DataEncryptionLimits.Default.MaxArgon2DegreeOfParallelism),
            new("Argon2 memory size in KiB", 41, DataEncryptionLimits.Default.MaxArgon2MemorySizeKb),
        ];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input, output, cipher, PasswordTestData.PasswordBytes(), Argon2Iterations, Argon2MemorySizeKb,
                Argon2DegreeOfParallelism, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(
                input, output, PasswordTestData.PasswordBytes(), limits, progress, cancellationToken);

        internal override Task DecryptWithWrongCredentialAsync(Stream input, Stream output) =>
            _service.DecryptAsync(input, output, PasswordTestData.WrongPasswordBytes(), null, null, CancellationToken.None);

        internal override Task EncryptFileAsync(
            string inputPath,
            string outputPath,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptFileAsync(
                inputPath, outputPath, cipher, PasswordTestData.PasswordBytes(), Argon2Iterations,
                Argon2MemorySizeKb, Argon2DegreeOfParallelism, progress, cancellationToken);

        internal override Task DecryptFileAsync(
            string inputPath,
            string outputPath,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, PasswordTestData.PasswordBytes(), null, progress, cancellationToken);

        internal override Task DecryptFileWithWrongCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(inputPath, outputPath, PasswordTestData.WrongPasswordBytes());

        internal override Task DecryptFileWithEmptyCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(inputPath, outputPath, Array.Empty<byte>());
    }

    private sealed class RsaHarness : ContainerMethodHarness
    {
        private readonly IRsaDataEncryptionService _service = new RsaDataEncryptionService(
            new BlockCipherServiceFactory(), new PublicKeyServiceFactory(), new HmacServiceFactory());

        internal override ContainerMethodKind Kind => ContainerMethodKind.Rsa;

        internal override EncryptionMethod Method => EncryptionMethod.Rsa;

        internal override int HeaderLength => RsaTestData.HeaderLength2048;

        internal override IReadOnlyList<Int32HeaderField> Int32Fields =>
        [
            new("RSA wrapped-key length", RsaTestData.WrappedKeyLengthOffset,
                DataEncryptionLimits.Default.MaxWrappedKeyLength),
        ];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input, output, cipher, RsaTestData.GoldenPublicKeyPem(), progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(
                input, output, RsaTestData.GoldenPrivateKeyPem(), null, limits, progress, cancellationToken);

        internal override Task DecryptWithWrongCredentialAsync(Stream input, Stream output) =>
            _service.DecryptAsync(
                input, output, RsaTestData.GoldenEncryptedPrivateKeyPem(), WrongPassphrase());

        internal override Task EncryptFileAsync(
            string inputPath,
            string outputPath,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptFileAsync(
                inputPath, outputPath, cipher, RsaTestData.GoldenPublicKeyPem(), progress, cancellationToken);

        internal override Task DecryptFileAsync(
            string inputPath,
            string outputPath,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, RsaTestData.GoldenPrivateKeyPem(), null, null, progress,
                cancellationToken);

        internal override Task DecryptFileWithWrongCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, RsaTestData.GoldenEncryptedPrivateKeyPem(), WrongPassphrase());

        internal override Task DecryptFileWithEmptyCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(inputPath, outputPath, string.Empty);

        private static char[] WrongPassphrase() => "not-the-passphrase".ToCharArray();
    }

    private sealed class MLKemHarness : ContainerMethodHarness
    {
        private readonly IMLKemDataEncryptionService _service = new MLKemDataEncryptionService(
            new BlockCipherServiceFactory(), new MLKemServiceFactory(), new HmacServiceFactory());

        private readonly byte[] _unrelatedPrivateKey =
            new MLKemServiceFactory().CreateMLKemService(KemParameterSet).GenerateKeyPair().privateKey;

        internal override ContainerMethodKind Kind => ContainerMethodKind.MLKem;

        internal override EncryptionMethod Method => EncryptionMethod.MLKem;

        internal override int HeaderLength => MLKemTestData.HeaderLengthOf(KemParameterSet);

        internal override IReadOnlyList<Int32HeaderField> Int32Fields =>
        [
            new("ML-KEM encapsulation length", MLKemTestData.EncapsulationLengthOffset,
                DataEncryptionLimits.Default.MaxEncapsulationLength),
        ];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input, output, cipher, MLKemTestData.GoldenPublicKey("512"), KemParameterSet, progress,
                cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(
                input, output, MLKemTestData.GoldenPrivateKey("512"), limits, progress, cancellationToken);

        internal override Task DecryptWithWrongCredentialAsync(Stream input, Stream output) =>
            _service.DecryptAsync(input, output, _unrelatedPrivateKey);

        internal override Task EncryptFileAsync(
            string inputPath,
            string outputPath,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptFileAsync(
                inputPath, outputPath, cipher, MLKemTestData.GoldenPublicKey("512"), KemParameterSet, progress,
                cancellationToken);

        internal override Task DecryptFileAsync(
            string inputPath,
            string outputPath,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, MLKemTestData.GoldenPrivateKey("512"), null, progress, cancellationToken);

        internal override Task DecryptFileWithWrongCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(inputPath, outputPath, _unrelatedPrivateKey);

        internal override Task DecryptFileWithEmptyCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(inputPath, outputPath, Array.Empty<byte>());
    }

    private sealed class HybridHarness : ContainerMethodHarness
    {
        private readonly IHybridDataEncryptionService _service = new HybridDataEncryptionService(
            new BlockCipherServiceFactory(), new PublicKeyServiceFactory(), new MLKemServiceFactory(),
            new HmacServiceFactory());

        // The wrong credential for this method is a wrong ML-KEM key alongside the right RSA one — see
        // DecryptWithWrongCredentialAsync's remarks on why that is the pointed half to get wrong.
        private readonly byte[] _unrelatedMLKemPrivateKey =
            new MLKemServiceFactory().CreateMLKemService(KemParameterSet).GenerateKeyPair().privateKey;

        internal override ContainerMethodKind Kind => ContainerMethodKind.Hybrid;

        internal override EncryptionMethod Method => EncryptionMethod.Hybrid;

        internal override int HeaderLength => HybridTestData.HeaderLengthOf(KemParameterSet);

        // Two Int32 fields, which no other method has. The second one's offset depends on the first
        // field's value, so it is computed rather than written down.
        internal override IReadOnlyList<Int32HeaderField> Int32Fields =>
        [
            new("RSA wrapped-key length", HybridTestData.WrappedSecretLengthOffset,
                DataEncryptionLimits.Default.MaxWrappedKeyLength),
            new("ML-KEM encapsulation length",
                HybridTestData.EncapsulationLengthOffset(HybridTestData.WrappedSecretLength2048),
                DataEncryptionLimits.Default.MaxEncapsulationLength),
        ];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input, output, cipher, RsaTestData.GoldenPublicKeyPem(),
                MLKemTestData.GoldenPublicKey("512"), KemParameterSet, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(
                input, output, RsaTestData.GoldenPrivateKeyPem(), MLKemTestData.GoldenPrivateKey("512"),
                null, limits, progress, cancellationToken);

        internal override Task DecryptWithWrongCredentialAsync(Stream input, Stream output) =>
            _service.DecryptAsync(
                input, output, RsaTestData.GoldenPrivateKeyPem(), _unrelatedMLKemPrivateKey);

        internal override Task EncryptFileAsync(
            string inputPath,
            string outputPath,
            Cipher cipher = Cipher.Aes256Gcm,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptFileAsync(
                inputPath, outputPath, cipher, RsaTestData.GoldenPublicKeyPem(),
                MLKemTestData.GoldenPublicKey("512"), KemParameterSet, progress, cancellationToken);

        internal override Task DecryptFileAsync(
            string inputPath,
            string outputPath,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, RsaTestData.GoldenPrivateKeyPem(),
                MLKemTestData.GoldenPrivateKey("512"), null, null, progress, cancellationToken);

        internal override Task DecryptFileWithWrongCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, RsaTestData.GoldenPrivateKeyPem(), _unrelatedMLKemPrivateKey);

        internal override Task DecryptFileWithEmptyCredentialAsync(string inputPath, string outputPath) =>
            _service.DecryptFileAsync(
                inputPath, outputPath, string.Empty, MLKemTestData.GoldenPrivateKey("512"));
    }
}
