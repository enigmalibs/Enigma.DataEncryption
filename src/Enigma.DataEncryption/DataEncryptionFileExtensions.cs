using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;

namespace Enigma.DataEncryption;

/// <summary>
/// File-path convenience wrappers over the stream-based encryption services: open the two files, run
/// the operation, and clean up after a failure.
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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();
}
