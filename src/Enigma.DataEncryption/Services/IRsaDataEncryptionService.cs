using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.DataEncryption;

/// <summary>
/// Encrypts and decrypts data with an RSA key pair, transporting a freshly generated 32-byte data key
/// under <b>RSAES-OAEP with SHA-256</b> (container method <c>0x03</c>).
/// </summary>
/// <remarks>
/// <para>
/// Produces a self-describing container: a (37 + <c>N</c>)-byte plaintext header — magic, method,
/// version, cipher, GCM nonce, wrapped-key length <c>N</c>, the wrapped key, key-confirmation tag —
/// followed by the AEAD payload, where <c>N</c> is the RSA modulus size in bytes. The complete header
/// is passed as GCM associated data, so any header edit is an authentication failure. See
/// <c>docs/format.md</c> §3.3.
/// </para>
/// <para>
/// The RSA operation covers only the 32-byte data key; the payload itself is symmetric, so file size
/// is unconstrained by the key size. No public-key fingerprint is stored — OAEP unwrap already fails
/// fast on the wrong key, and the key-confirmation tag covers wrong-credential detection uniformly.
/// </para>
/// <para>Implementations are stateless and safe for concurrent use.</para>
/// </remarks>
public interface IRsaDataEncryptionService
{
    /// <summary>
    /// Encrypts <paramref name="input"/> into <paramref name="output"/> for the holder of the private
    /// key matching <paramref name="publicKeyPem"/>.
    /// </summary>
    /// <param name="input">The plaintext stream, read to its end.</param>
    /// <param name="output">The stream the container is written to — header first, then payload.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="publicKeyPem">
    /// The recipient's RSA public key, PEM-encoded (a <c>PUBLIC KEY</c> or <c>RSA PUBLIC KEY</c> PEM).
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <remarks>
    /// Neither stream is disposed, and both are left wherever the operation ended. The data key and
    /// the key-confirmation key generated internally are cleared before returning; the
    /// caller-supplied key material is not.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="publicKeyPem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="publicKeyPem"/> is empty or not a readable RSA public-key PEM, or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string publicKeyPem,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts an RSA container from <paramref name="input"/> into <paramref name="output"/>.
    /// </summary>
    /// <param name="input">
    /// The container stream, positioned at the magic. <b>It need not be seekable</b> — the header is
    /// read forward, once, and the payload is streamed from wherever it ended.
    /// </param>
    /// <param name="output">The stream the recovered plaintext is written to.</param>
    /// <param name="privateKeyPem">
    /// The recipient's RSA private key, PEM-encoded. May be an encrypted private-key PEM, in which
    /// case <paramref name="keyPassword"/> is required.
    /// </param>
    /// <param name="keyPassword">
    /// The passphrase protecting an encrypted <paramref name="privateKeyPem"/>, or
    /// <see langword="null"/> if the PEM is unencrypted. The array is neither mutated nor cleared:
    /// the caller owns its lifetime.
    /// </param>
    /// <param name="limits">
    /// Bounds applied to the header's wrapped-key length before it is allocated or read. Pass
    /// <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <remarks>
    /// Neither stream is disposed, and both are left wherever the operation ended. The unwrapped data
    /// key and the key-confirmation key are cleared before returning; the caller-supplied
    /// <paramref name="privateKeyPem"/> and <paramref name="keyPassword"/> are not.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="privateKeyPem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="privateKeyPem"/> is empty, or is not a readable RSA private-key PEM. A malformed or undecryptable PEM is a credential-supply error and propagates from Enigma.Core unwrapped.</exception>
    /// <exception cref="DataEncryptionFormatException">The header is not a valid RSA container, or the wrapped-key length is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The private key does not match the container (OAEP unwrap failure or key-confirmation mismatch), or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task DecryptAsync(
        Stream input,
        Stream output,
        string privateKeyPem,
        char[]? keyPassword = null,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
