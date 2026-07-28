using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption;

/// <summary>
/// File-path convenience wrappers over the stream-based encryption services: open the two files, run
/// the operation, and clean up after a failure. Fourteen methods — an encrypt/decrypt pair per
/// credential shape.
/// </summary>
/// <remarks>
/// <para>Every method in this class shares three deliberate, load-bearing semantics.</para>
/// <list type="number">
///   <item><description>
///     <b>Input</b> is opened <c>FileMode.Open</c>, <c>FileAccess.Read</c>, <c>FileShare.Read</c>,
///     <c>bufferSize: 4096</c>, <c>useAsync: true</c> — so other readers may hold it open concurrently.
///   </description></item>
///   <item><description>
///     <b>Output</b> is opened <c>FileMode.Create</c> — <b>create-or-overwrite</b>: an existing file at
///     <c>outputPath</c> is truncated without warning — with <c>FileAccess.Write</c>,
///     <c>FileShare.None</c>, <c>bufferSize: 4096</c>, <c>useAsync: true</c>.
///   </description></item>
///   <item><description>
///     <b>On any failure — including cancellation — the partial output file is deleted</b> before the
///     exception propagates. A failed decrypt therefore never leaves a truncated plaintext on disk.
///     The delete is best-effort: if it fails, that failure is swallowed rather than allowed to mask
///     the original exception.
///   </description></item>
/// </list>
/// <para>
/// <b>Arguments are validated before either file is opened.</b> Since the output is opened
/// <c>FileMode.Create</c>, validating afterwards would truncate an existing file only to delete it
/// again — so a bad argument leaves the filesystem untouched, and the create-then-delete cycle is
/// reserved for failures that genuinely required the attempt.
/// </para>
/// <para>
/// These are extension methods on the service interfaces rather than members of the implementations,
/// so they compose with any implementation — including a test double.
/// </para>
/// <para>
/// Credential handling matches the underlying stream overloads exactly: caller-supplied arrays are
/// neither mutated nor cleared, and <c>char[]</c> passwords are UTF-8-encoded into a temporary buffer
/// that is cleared before returning. Progress reports <b>payload bytes processed</b>; header bytes are
/// not counted.
/// </para>
/// </remarks>
public static class DataEncryptionFileExtensions
{
    /// <summary>
    /// The <see cref="FileStream"/> buffer size both files are opened with, in bytes.
    /// </summary>
    private const int FileBufferSize = 4096;

    // ---------------------------------------------------------------------------------------------
    // PBKDF2
    // ---------------------------------------------------------------------------------------------

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> with PBKDF2, using a password supplied as raw bytes.</summary>
    /// <param name="service">The PBKDF2 service performing the operation.</param>
    /// <param name="inputPath">Path of the plaintext file to read.</param>
    /// <param name="outputPath">Path of the container file to write. <b>Overwritten if it exists</b>; deleted if the operation fails.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="password">The password bytes, used as supplied and never cleared by this method.</param>
    /// <param name="iterations">The PBKDF2 iteration count. Defaults to <see cref="DataEncryptionDefaults.Pbkdf2Iterations"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not greater than zero.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task EncryptFileAsync(
        this IPbkdf2DataEncryptionService service,
        string inputPath,
        string outputPath,
        Cipher cipher,
        byte[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        PasswordCredential.Validate(password, nameof(password));
        RequirePositive(iterations, nameof(iterations), "The PBKDF2 iteration count");

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.EncryptAsync(
                input, output, cipher, password, iterations, progress, cancellationToken));
    }

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> with PBKDF2, using a password supplied as characters.</summary>
    /// <param name="service">The PBKDF2 service performing the operation.</param>
    /// <param name="inputPath">Path of the plaintext file to read.</param>
    /// <param name="outputPath">Path of the container file to write. <b>Overwritten if it exists</b>; deleted if the operation fails.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="password">The password characters. UTF-8-encoded into a temporary buffer that is cleared before returning; the caller's array is untouched.</param>
    /// <param name="iterations">The PBKDF2 iteration count. Defaults to <see cref="DataEncryptionDefaults.Pbkdf2Iterations"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not greater than zero.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task EncryptFileAsync(
        this IPbkdf2DataEncryptionService service,
        string inputPath,
        string outputPath,
        Cipher cipher,
        char[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        PasswordCredential.Validate(password, nameof(password));
        RequirePositive(iterations, nameof(iterations), "The PBKDF2 iteration count");

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.EncryptAsync(
                input, output, cipher, password, iterations, progress, cancellationToken));
    }

    /// <summary>Decrypts the PBKDF2 container at <paramref name="inputPath"/> to <paramref name="outputPath"/>, using a password supplied as raw bytes.</summary>
    /// <param name="service">The PBKDF2 service performing the operation.</param>
    /// <param name="inputPath">Path of the container file to read.</param>
    /// <param name="outputPath">Path of the plaintext file to write. <b>Overwritten if it exists</b>; deleted if the operation fails, so a wrong password leaves no truncated plaintext behind.</param>
    /// <param name="password">The password bytes, used as supplied and never cleared by this method.</param>
    /// <param name="limits">Header bounds applied before any key-derivation work. Pass <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="DataEncryptionFormatException">The file is not a valid PBKDF2 container, or a field is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The password is wrong, or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task DecryptFileAsync(
        this IPbkdf2DataEncryptionService service,
        string inputPath,
        string outputPath,
        byte[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        PasswordCredential.Validate(password, nameof(password));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.DecryptAsync(
                input, output, password, limits, progress, cancellationToken));
    }

    /// <summary>Decrypts the PBKDF2 container at <paramref name="inputPath"/> to <paramref name="outputPath"/>, using a password supplied as characters.</summary>
    /// <param name="service">The PBKDF2 service performing the operation.</param>
    /// <param name="inputPath">Path of the container file to read.</param>
    /// <param name="outputPath">Path of the plaintext file to write. <b>Overwritten if it exists</b>; deleted if the operation fails, so a wrong password leaves no truncated plaintext behind.</param>
    /// <param name="password">The password characters. UTF-8-encoded into a temporary buffer that is cleared before returning; the caller's array is untouched.</param>
    /// <param name="limits">Header bounds applied before any key-derivation work. Pass <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="DataEncryptionFormatException">The file is not a valid PBKDF2 container, or a field is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The password is wrong, or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task DecryptFileAsync(
        this IPbkdf2DataEncryptionService service,
        string inputPath,
        string outputPath,
        char[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        PasswordCredential.Validate(password, nameof(password));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.DecryptAsync(
                input, output, password, limits, progress, cancellationToken));
    }

    // ---------------------------------------------------------------------------------------------
    // Argon2
    // ---------------------------------------------------------------------------------------------

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> with Argon2id, using a password supplied as raw bytes.</summary>
    /// <param name="service">The Argon2 service performing the operation.</param>
    /// <param name="inputPath">Path of the plaintext file to read.</param>
    /// <param name="outputPath">Path of the container file to write. <b>Overwritten if it exists</b>; deleted if the operation fails.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="password">The password bytes, used as supplied and never cleared by this method.</param>
    /// <param name="iterations">Passes over memory. Defaults to <see cref="DataEncryptionDefaults.Argon2Iterations"/>.</param>
    /// <param name="memorySizeKb">Memory cost in kibibytes. Defaults to <see cref="DataEncryptionDefaults.Argon2MemorySizeKb"/>.</param>
    /// <param name="degreeOfParallelism">Parallel lanes. Defaults to <see cref="DataEncryptionDefaults.Argon2DegreeOfParallelism"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/>, <paramref name="memorySizeKb"/> or <paramref name="degreeOfParallelism"/> is not greater than zero.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task EncryptFileAsync(
        this IArgon2DataEncryptionService service,
        string inputPath,
        string outputPath,
        Cipher cipher,
        byte[] password,
        int iterations = DataEncryptionDefaults.Argon2Iterations,
        int memorySizeKb = DataEncryptionDefaults.Argon2MemorySizeKb,
        int degreeOfParallelism = DataEncryptionDefaults.Argon2DegreeOfParallelism,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        PasswordCredential.Validate(password, nameof(password));
        ValidateArgon2Costs(iterations, memorySizeKb, degreeOfParallelism);

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.EncryptAsync(
                input, output, cipher, password, iterations, memorySizeKb, degreeOfParallelism,
                progress, cancellationToken));
    }

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> with Argon2id, using a password supplied as characters.</summary>
    /// <param name="service">The Argon2 service performing the operation.</param>
    /// <param name="inputPath">Path of the plaintext file to read.</param>
    /// <param name="outputPath">Path of the container file to write. <b>Overwritten if it exists</b>; deleted if the operation fails.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="password">The password characters. UTF-8-encoded into a temporary buffer that is cleared before returning; the caller's array is untouched.</param>
    /// <param name="iterations">Passes over memory. Defaults to <see cref="DataEncryptionDefaults.Argon2Iterations"/>.</param>
    /// <param name="memorySizeKb">Memory cost in kibibytes. Defaults to <see cref="DataEncryptionDefaults.Argon2MemorySizeKb"/>.</param>
    /// <param name="degreeOfParallelism">Parallel lanes. Defaults to <see cref="DataEncryptionDefaults.Argon2DegreeOfParallelism"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/>, <paramref name="memorySizeKb"/> or <paramref name="degreeOfParallelism"/> is not greater than zero.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task EncryptFileAsync(
        this IArgon2DataEncryptionService service,
        string inputPath,
        string outputPath,
        Cipher cipher,
        char[] password,
        int iterations = DataEncryptionDefaults.Argon2Iterations,
        int memorySizeKb = DataEncryptionDefaults.Argon2MemorySizeKb,
        int degreeOfParallelism = DataEncryptionDefaults.Argon2DegreeOfParallelism,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        PasswordCredential.Validate(password, nameof(password));
        ValidateArgon2Costs(iterations, memorySizeKb, degreeOfParallelism);

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.EncryptAsync(
                input, output, cipher, password, iterations, memorySizeKb, degreeOfParallelism,
                progress, cancellationToken));
    }

    /// <summary>Decrypts the Argon2 container at <paramref name="inputPath"/> to <paramref name="outputPath"/>, using a password supplied as raw bytes.</summary>
    /// <param name="service">The Argon2 service performing the operation.</param>
    /// <param name="inputPath">Path of the container file to read.</param>
    /// <param name="outputPath">Path of the plaintext file to write. <b>Overwritten if it exists</b>; deleted if the operation fails, so a wrong password leaves no truncated plaintext behind.</param>
    /// <param name="password">The password bytes, used as supplied and never cleared by this method.</param>
    /// <param name="limits">Header bounds applied before any memory is allocated or derivation work done. Pass <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="DataEncryptionFormatException">The file is not a valid Argon2 container, or a cost field is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The password is wrong, or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task DecryptFileAsync(
        this IArgon2DataEncryptionService service,
        string inputPath,
        string outputPath,
        byte[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        PasswordCredential.Validate(password, nameof(password));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.DecryptAsync(
                input, output, password, limits, progress, cancellationToken));
    }

    /// <summary>Decrypts the Argon2 container at <paramref name="inputPath"/> to <paramref name="outputPath"/>, using a password supplied as characters.</summary>
    /// <param name="service">The Argon2 service performing the operation.</param>
    /// <param name="inputPath">Path of the container file to read.</param>
    /// <param name="outputPath">Path of the plaintext file to write. <b>Overwritten if it exists</b>; deleted if the operation fails, so a wrong password leaves no truncated plaintext behind.</param>
    /// <param name="password">The password characters. UTF-8-encoded into a temporary buffer that is cleared before returning; the caller's array is untouched.</param>
    /// <param name="limits">Header bounds applied before any memory is allocated or derivation work done. Pass <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="password"/> is empty.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="DataEncryptionFormatException">The file is not a valid Argon2 container, or a cost field is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The password is wrong, or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task DecryptFileAsync(
        this IArgon2DataEncryptionService service,
        string inputPath,
        string outputPath,
        char[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        PasswordCredential.Validate(password, nameof(password));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.DecryptAsync(
                input, output, password, limits, progress, cancellationToken));
    }

    // ---------------------------------------------------------------------------------------------
    // RSA
    // ---------------------------------------------------------------------------------------------

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> for the holder of the private key matching <paramref name="publicKeyPem"/>.</summary>
    /// <param name="service">The RSA service performing the operation.</param>
    /// <param name="inputPath">Path of the plaintext file to read.</param>
    /// <param name="outputPath">Path of the container file to write. <b>Overwritten if it exists</b>; deleted if the operation fails.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="publicKeyPem">The recipient's RSA public key, PEM-encoded.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="publicKeyPem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="publicKeyPem"/> is empty or not a readable RSA public-key PEM, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task EncryptFileAsync(
        this IRsaDataEncryptionService service,
        string inputPath,
        string outputPath,
        Cipher cipher,
        string publicKeyPem,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        ValidatePem(publicKeyPem, nameof(publicKeyPem));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.EncryptAsync(
                input, output, cipher, publicKeyPem, progress, cancellationToken));
    }

    /// <summary>Decrypts the RSA container at <paramref name="inputPath"/> to <paramref name="outputPath"/>.</summary>
    /// <param name="service">The RSA service performing the operation.</param>
    /// <param name="inputPath">Path of the container file to read.</param>
    /// <param name="outputPath">Path of the plaintext file to write. <b>Overwritten if it exists</b>; deleted if the operation fails, so a wrong key leaves no truncated plaintext behind.</param>
    /// <param name="privateKeyPem">The recipient's RSA private key, PEM-encoded; may be an encrypted private-key PEM.</param>
    /// <param name="keyPassword">The passphrase protecting an encrypted <paramref name="privateKeyPem"/>, or <see langword="null"/> if it is unencrypted. Never cleared by this method.</param>
    /// <param name="limits">Header bounds applied before the wrapped key is allocated or read. Pass <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="privateKeyPem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="privateKeyPem"/> is empty or not a readable RSA private-key PEM.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="DataEncryptionFormatException">The file is not a valid RSA container, or the wrapped-key length is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The private key does not match the container, or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task DecryptFileAsync(
        this IRsaDataEncryptionService service,
        string inputPath,
        string outputPath,
        string privateKeyPem,
        char[]? keyPassword = null,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        ValidatePem(privateKeyPem, nameof(privateKeyPem));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.DecryptAsync(
                input, output, privateKeyPem, keyPassword, limits, progress, cancellationToken));
    }

    // ---------------------------------------------------------------------------------------------
    // ML-KEM
    // ---------------------------------------------------------------------------------------------

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> for the holder of the private key matching <paramref name="publicKey"/>.</summary>
    /// <param name="service">The ML-KEM service performing the operation.</param>
    /// <param name="inputPath">Path of the plaintext file to read.</param>
    /// <param name="outputPath">Path of the container file to write. <b>Overwritten if it exists</b>; deleted if the operation fails.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="publicKey">The recipient's ML-KEM public key, in its raw FIPS 203 encoding.</param>
    /// <param name="parameterSet">The ML-KEM parameter set to encapsulate under, written into the header. Defaults to <see cref="MLKemParameterSet.MLKem1024"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="publicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="publicKey"/> is empty or the wrong length for <paramref name="parameterSet"/>, or <paramref name="cipher"/> / <paramref name="parameterSet"/> is not a defined value.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task EncryptFileAsync(
        this IMLKemDataEncryptionService service,
        string inputPath,
        string outputPath,
        Cipher cipher,
        byte[] publicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        ValidateKemKey(publicKey, nameof(publicKey));
        MLKemParameterSetWire.ValidateArgument(parameterSet, nameof(parameterSet));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.EncryptAsync(
                input, output, cipher, publicKey, parameterSet, progress, cancellationToken));
    }

    /// <summary>Decrypts the ML-KEM container at <paramref name="inputPath"/> to <paramref name="outputPath"/>.</summary>
    /// <param name="service">The ML-KEM service performing the operation.</param>
    /// <param name="inputPath">Path of the container file to read.</param>
    /// <param name="outputPath">Path of the plaintext file to write. <b>Overwritten if it exists</b>; deleted if the operation fails, so a wrong key leaves no truncated plaintext behind.</param>
    /// <param name="privateKey">The recipient's ML-KEM private key, in its raw expanded FIPS 203 encoding. Never cleared by this method.</param>
    /// <param name="limits">Header bounds applied before the encapsulation is allocated or read. Pass <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <remarks>The parameter set is read from the container's header, so it is not a parameter here.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/> or <paramref name="privateKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or <paramref name="privateKey"/> is empty or the wrong length for the header's parameter set.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="DataEncryptionFormatException">The file is not a valid ML-KEM container, its parameter-set byte is undefined, or the encapsulation length is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The private key does not match the container, or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task DecryptFileAsync(
        this IMLKemDataEncryptionService service,
        string inputPath,
        string outputPath,
        byte[] privateKey,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        ValidateKemKey(privateKey, nameof(privateKey));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.DecryptAsync(
                input, output, privateKey, limits, progress, cancellationToken));
    }

    // ---------------------------------------------------------------------------------------------
    // Hybrid RSA + ML-KEM
    // ---------------------------------------------------------------------------------------------

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> for the holder of <b>both</b> private keys matching <paramref name="rsaPublicKeyPem"/> and <paramref name="mlKemPublicKey"/>.</summary>
    /// <param name="service">The hybrid service performing the operation.</param>
    /// <param name="inputPath">Path of the plaintext file to read.</param>
    /// <param name="outputPath">Path of the container file to write. <b>Overwritten if it exists</b>; deleted if the operation fails.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="rsaPublicKeyPem">The recipient's RSA public key, PEM-encoded.</param>
    /// <param name="mlKemPublicKey">The recipient's ML-KEM public key, in its raw FIPS 203 encoding.</param>
    /// <param name="parameterSet">The ML-KEM parameter set to encapsulate under, written into the header. Defaults to <see cref="MLKemParameterSet.MLKem1024"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <remarks>Both credentials are required — see <see cref="IHybridDataEncryptionService"/>.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/>, <paramref name="rsaPublicKeyPem"/> or <paramref name="mlKemPublicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or a key is empty or unusable, or <paramref name="cipher"/> / <paramref name="parameterSet"/> is not a defined value.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task EncryptFileAsync(
        this IHybridDataEncryptionService service,
        string inputPath,
        string outputPath,
        Cipher cipher,
        string rsaPublicKeyPem,
        byte[] mlKemPublicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        CipherResolver.ValidateArgument(cipher, nameof(cipher));
        ValidatePem(rsaPublicKeyPem, nameof(rsaPublicKeyPem));
        ValidateKemKey(mlKemPublicKey, nameof(mlKemPublicKey));
        MLKemParameterSetWire.ValidateArgument(parameterSet, nameof(parameterSet));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.EncryptAsync(
                input, output, cipher, rsaPublicKeyPem, mlKemPublicKey, parameterSet, progress,
                cancellationToken));
    }

    /// <summary>Decrypts the hybrid container at <paramref name="inputPath"/> to <paramref name="outputPath"/>, using <b>both</b> private keys.</summary>
    /// <param name="service">The hybrid service performing the operation.</param>
    /// <param name="inputPath">Path of the container file to read.</param>
    /// <param name="outputPath">Path of the plaintext file to write. <b>Overwritten if it exists</b>; deleted if the operation fails, so a wrong key leaves no truncated plaintext behind.</param>
    /// <param name="rsaPrivateKeyPem">The recipient's RSA private key, PEM-encoded; may be an encrypted private-key PEM.</param>
    /// <param name="mlKemPrivateKey">The recipient's ML-KEM private key, in its raw expanded FIPS 203 encoding. Never cleared by this method.</param>
    /// <param name="rsaKeyPassword">The passphrase protecting an encrypted <paramref name="rsaPrivateKeyPem"/>, or <see langword="null"/>. Never cleared by this method.</param>
    /// <param name="limits">Header bounds applied before either variable-length field is allocated or read. Pass <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.</param>
    /// <param name="progress">Optional progress receiver, reporting <b>payload bytes processed</b>.</param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <remarks>The parameter set is read from the container's header, so it is not a parameter here.</remarks>
    /// <exception cref="ArgumentNullException"><paramref name="service"/>, <paramref name="inputPath"/>, <paramref name="outputPath"/>, <paramref name="rsaPrivateKeyPem"/> or <paramref name="mlKemPrivateKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">A path is empty, or a key is empty or unparseable.</exception>
    /// <exception cref="IOException">A file could not be opened, read or written.</exception>
    /// <exception cref="DataEncryptionFormatException">The file is not a valid hybrid container, its parameter-set byte is undefined, or a length field is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">Either private key does not match the container, or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled; the partial output file has been deleted.</exception>
    public static Task DecryptFileAsync(
        this IHybridDataEncryptionService service,
        string inputPath,
        string outputPath,
        string rsaPrivateKeyPem,
        byte[] mlKemPrivateKey,
        char[]? rsaKeyPassword = null,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ValidateTarget(service, inputPath, outputPath);
        ValidatePem(rsaPrivateKeyPem, nameof(rsaPrivateKeyPem));
        ValidateKemKey(mlKemPrivateKey, nameof(mlKemPrivateKey));

        return RunAsync(
            inputPath,
            outputPath,
            (input, output) => service.DecryptAsync(
                input, output, rsaPrivateKeyPem, mlKemPrivateKey, rsaKeyPassword, limits, progress,
                cancellationToken));
    }

    // ---------------------------------------------------------------------------------------------
    // The shared plumbing
    // ---------------------------------------------------------------------------------------------

    /// <summary>
    /// Opens both files, runs <paramref name="operation"/> over them, and deletes the output on any
    /// failure.
    /// </summary>
    /// <param name="inputPath">The file to read.</param>
    /// <param name="outputPath">The file to write, create-or-overwrite.</param>
    /// <param name="operation">The stream-based service call to delegate to.</param>
    /// <returns>A task representing the operation.</returns>
    /// <remarks>
    /// <para>
    /// The output handle lives in a nested scope <b>inside</b> the <c>try</c>, so it is flushed and closed
    /// before the <c>catch</c> runs. Deleting a file this process still holds open fails on Windows, so the
    /// ordering is what makes the cleanup actually work rather than merely be attempted.
    /// </para>
    /// <para>
    /// A failure opening the input happens outside the <c>try</c>, where there is no output file to clean
    /// up yet — the one case that must not delete anything.
    /// </para>
    /// </remarks>
    private static async Task RunAsync(
        string inputPath,
        string outputPath,
        Func<Stream, Stream, Task> operation)
    {
        using FileStream input = new(
            inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferSize, useAsync: true);

        try
        {
            using (FileStream output = new(
                       outputPath, FileMode.Create, FileAccess.Write, FileShare.None, FileBufferSize,
                       useAsync: true))
            {
                await operation(input, output).ConfigureAwait(false);
            }
        }
        catch
        {
            TryDelete(outputPath);
            throw;
        }
    }

    /// <summary>Deletes a file, ignoring the failure modes a cleanup path must not turn into its own error.</summary>
    /// <param name="path">The file to remove.</param>
    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException)
        {
            // Best-effort by contract: the exception that caused the cleanup is the one worth reporting,
            // and replacing it with "could not delete the partial output" would hide the real failure.
        }
        catch (UnauthorizedAccessException)
        {
            // Same reasoning: a read-only or locked output file is not why the operation failed.
        }
    }

    /// <summary>Validates the receiver and the two paths — everything these wrappers own themselves.</summary>
    /// <param name="service">The service the extension method was invoked on.</param>
    /// <param name="inputPath">The caller's input path.</param>
    /// <param name="outputPath">The caller's output path.</param>
    /// <exception cref="ArgumentNullException">Any argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Either path is empty.</exception>
    private static void ValidateTarget(object service, string inputPath, string outputPath)
    {
        if (service is null) throw new ArgumentNullException(nameof(service));
        if (inputPath is null) throw new ArgumentNullException(nameof(inputPath));
        if (outputPath is null) throw new ArgumentNullException(nameof(outputPath));

        if (inputPath.Length == 0)
        {
            throw new ArgumentException("The input path must not be empty.", nameof(inputPath));
        }

        if (outputPath.Length == 0)
        {
            throw new ArgumentException("The output path must not be empty.", nameof(outputPath));
        }
    }

    /// <summary>Validates a PEM-encoded key, matching <see cref="RsaDataEncryptionService"/>'s own check.</summary>
    /// <param name="pem">The caller's PEM string.</param>
    /// <param name="paramName">The name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentNullException"><paramref name="pem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="pem"/> is empty.</exception>
    private static void ValidatePem(string pem, string paramName)
    {
        if (pem is null) throw new ArgumentNullException(paramName);

        if (pem.Length == 0)
        {
            throw new ArgumentException("The PEM-encoded key must not be empty.", paramName);
        }
    }

    /// <summary>Validates a raw ML-KEM key, matching <see cref="MLKemDataEncryptionService"/>'s own check.</summary>
    /// <param name="key">The caller's key bytes.</param>
    /// <param name="paramName">The name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="key"/> is empty.</exception>
    private static void ValidateKemKey(byte[] key, string paramName)
    {
        if (key is null) throw new ArgumentNullException(paramName);

        if (key.Length == 0)
        {
            throw new ArgumentException("The ML-KEM key must not be empty.", paramName);
        }
    }

    /// <summary>Bounds the three Argon2 cost parameters, matching <see cref="Argon2DataEncryptionService"/>.</summary>
    /// <param name="iterations">Passes over memory.</param>
    /// <param name="memorySizeKb">Memory cost in kibibytes.</param>
    /// <param name="degreeOfParallelism">Parallel lanes.</param>
    /// <exception cref="ArgumentOutOfRangeException">Any of the three is not greater than zero.</exception>
    private static void ValidateArgon2Costs(int iterations, int memorySizeKb, int degreeOfParallelism)
    {
        RequirePositive(iterations, nameof(iterations), "The Argon2 iteration count");
        RequirePositive(memorySizeKb, nameof(memorySizeKb), "The Argon2 memory size in KiB");
        RequirePositive(degreeOfParallelism, nameof(degreeOfParallelism), "The Argon2 degree of parallelism");
    }

    /// <summary>Rejects a cost parameter that is not greater than zero.</summary>
    /// <param name="value">The value supplied.</param>
    /// <param name="paramName">The name of the caller's parameter, for the exception.</param>
    /// <param name="description">How to name the parameter in the message.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value"/> is not greater than zero.</exception>
    private static void RequirePositive(int value, string paramName, string description)
    {
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(paramName, value, $"{description} must be greater than zero.");
        }
    }
}
