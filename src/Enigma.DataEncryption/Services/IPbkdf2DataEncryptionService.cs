using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.DataEncryption;

/// <summary>
/// Encrypts and decrypts data with a password, deriving the 32-byte data key with
/// <b>PBKDF2-HMAC-SHA256</b> (container method <c>0x01</c>).
/// </summary>
/// <remarks>
/// <para>
/// Produces a self-describing container: a 53-byte plaintext header (magic, method, version, cipher,
/// GCM nonce, salt, iteration count, key-confirmation tag) followed by the AEAD payload. The complete
/// header is passed as GCM associated data, so any header edit is an authentication failure. See
/// <c>docs/format.md</c> §3.1.
/// </para>
/// <para>
/// Prefer <see cref="IArgon2DataEncryptionService"/> for new work where the extra cost is acceptable:
/// Argon2id is memory-hard and therefore much more expensive to attack on GPUs. PBKDF2 remains here
/// for interoperability and for constrained environments.
/// </para>
/// <para>Implementations are stateless and safe for concurrent use.</para>
/// </remarks>
public interface IPbkdf2DataEncryptionService
{
    /// <summary>
    /// Encrypts <paramref name="input"/> into <paramref name="output"/> under a password supplied as
    /// raw bytes.
    /// </summary>
    /// <param name="input">The plaintext stream, read to its end.</param>
    /// <param name="output">The stream the container is written to — header first, then payload.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="password">
    /// The password bytes, used as supplied. The array is neither mutated nor cleared: the caller
    /// owns both its encoding and its lifetime.
    /// </param>
    /// <param name="iterations">
    /// The PBKDF2 iteration count, written into the header. Defaults to
    /// <see cref="DataEncryptionDefaults.Pbkdf2Iterations"/> (600,000, the OWASP 2023 floor).
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <remarks>
    /// Neither stream is disposed, and both are left wherever the operation ended. The data key and
    /// the key-confirmation key derived internally are cleared before returning; the caller-supplied
    /// <paramref name="password"/> is not.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not greater than zero.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Encrypts <paramref name="input"/> into <paramref name="output"/> under a password supplied as
    /// characters.
    /// </summary>
    /// <param name="input">The plaintext stream, read to its end.</param>
    /// <param name="output">The stream the container is written to — header first, then payload.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="password">
    /// The password characters. They are UTF-8-encoded into a temporary buffer which is cleared
    /// before returning; the caller's own array is neither mutated nor cleared.
    /// </param>
    /// <param name="iterations">
    /// The PBKDF2 iteration count, written into the header. Defaults to
    /// <see cref="DataEncryptionDefaults.Pbkdf2Iterations"/> (600,000, the OWASP 2023 floor).
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <remarks>
    /// Neither stream is disposed, and both are left wherever the operation ended. The data key and
    /// the key-confirmation key derived internally are cleared before returning; the caller-supplied
    /// <paramref name="password"/> is not.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is not greater than zero.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        char[] password,
        int iterations = DataEncryptionDefaults.Pbkdf2Iterations,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a PBKDF2 container from <paramref name="input"/> into <paramref name="output"/>,
    /// under a password supplied as raw bytes.
    /// </summary>
    /// <param name="input">
    /// The container stream, positioned at the magic. <b>It need not be seekable</b> — the header is
    /// read forward, once, and the payload is streamed from wherever it ended.
    /// </param>
    /// <param name="output">The stream the recovered plaintext is written to.</param>
    /// <param name="password">
    /// The password bytes, used as supplied. The array is neither mutated nor cleared: the caller
    /// owns both its encoding and its lifetime.
    /// </param>
    /// <param name="limits">
    /// Bounds applied to the header's iteration count before any key-derivation work. Pass
    /// <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <remarks>
    /// Neither stream is disposed, and both are left wherever the operation ended. The data key and
    /// the key-confirmation key derived internally are cleared before returning; the caller-supplied
    /// <paramref name="password"/> is not.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    /// <exception cref="DataEncryptionFormatException">The header is not a valid PBKDF2 container, or a field is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The password is wrong (key-confirmation mismatch), or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a PBKDF2 container from <paramref name="input"/> into <paramref name="output"/>,
    /// under a password supplied as characters.
    /// </summary>
    /// <param name="input">
    /// The container stream, positioned at the magic. <b>It need not be seekable</b> — the header is
    /// read forward, once, and the payload is streamed from wherever it ended.
    /// </param>
    /// <param name="output">The stream the recovered plaintext is written to.</param>
    /// <param name="password">
    /// The password characters. They are UTF-8-encoded into a temporary buffer which is cleared
    /// before returning; the caller's own array is neither mutated nor cleared.
    /// </param>
    /// <param name="limits">
    /// Bounds applied to the header's iteration count before any key-derivation work. Pass
    /// <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <remarks>
    /// Neither stream is disposed, and both are left wherever the operation ended. The data key and
    /// the key-confirmation key derived internally are cleared before returning; the caller-supplied
    /// <paramref name="password"/> is not.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    /// <exception cref="DataEncryptionFormatException">The header is not a valid PBKDF2 container, or a field is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The password is wrong (key-confirmation mismatch), or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task DecryptAsync(
        Stream input,
        Stream output,
        char[] password,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
