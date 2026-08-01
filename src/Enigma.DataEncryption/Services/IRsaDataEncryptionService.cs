using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.PublicKey;

namespace Enigma.DataEncryption;

/// <summary>
/// Encrypts and decrypts data with an RSA key pair, transporting a freshly generated 32-byte data key
/// under <b>RSAES-OAEP</b> (container method <c>0x03</c>).
/// </summary>
/// <remarks>
/// <para>
/// Produces a self-describing container: a (38 + <c>N</c>)-byte plaintext header — magic, method,
/// version, cipher, OAEP hash, GCM nonce, wrapped-key length <c>N</c>, the wrapped key,
/// key-confirmation tag — followed by the AEAD payload, where <c>N</c> is the RSA modulus size in
/// bytes. The complete header is passed as GCM associated data, so any header edit is an authentication
/// failure. See <c>docs/format.md</c> §3.3.
/// </para>
/// <para>
/// <b>The OAEP padding hash is selected at encryption time and recorded in the header.</b> SHA-256 (the
/// default), SHA-384 and SHA-512 are accepted; SHA-1 is not. Decryption therefore takes no hash
/// parameter — it reads the one the container names. The choice is offered for policy compliance rather
/// than strength: OAEP asks no collision resistance of its hash, so the three are equivalent here.
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
    /// <param name="oaepHash">
    /// The hash backing the OAEP padding, recorded in the header so the reader can reproduce it.
    /// <see cref="RsaOaepHash.Sha256"/> (the default), <see cref="RsaOaepHash.Sha384"/> and
    /// <see cref="RsaOaepHash.Sha512"/> are accepted; <see cref="RsaOaepHash.Sha1"/> is rejected.
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <remarks>
    /// <para>
    /// Neither stream is disposed, and both are left wherever the operation ended. The data key and
    /// the key-confirmation key generated internally are cleared before returning; the
    /// caller-supplied key material is not.
    /// </para>
    /// <para>
    /// <b>A larger <paramref name="oaepHash"/> needs a larger key.</b> Wrapping the 32-byte data key
    /// requires an RSA modulus of at least <c>2·hLen + 34</c> bytes (RFC 8017 §7.1.1): 98 for SHA-256,
    /// 130 for SHA-384 and 162 for SHA-512. RSA-2048 and above satisfy all three; RSA-1024 satisfies
    /// only SHA-256. A key that is too small is reported as an <see cref="ArgumentException"/> on
    /// <paramref name="publicKeyPem"/>, before anything is written.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="publicKeyPem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="publicKeyPem"/> is empty, not a readable RSA public-key PEM, or too small to wrap a 32-byte data key under <paramref name="oaepHash"/> (the underlying <see cref="System.Security.Cryptography.CryptographicException"/> kept as <see cref="System.Exception.InnerException"/>); or <paramref name="cipher"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="oaepHash"/> is <see cref="RsaOaepHash.Sha1"/>, which this format does not accept, or is not a defined value.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string publicKeyPem,
        RsaOaepHash oaepHash = RsaOaepHash.Sha256,
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
    /// <para>
    /// Neither stream is disposed, and both are left wherever the operation ended. The unwrapped data
    /// key and the key-confirmation key are cleared before returning; the caller-supplied
    /// <paramref name="privateKeyPem"/> and <paramref name="keyPassword"/> are not.
    /// </para>
    /// <para>
    /// <b>There is no hash parameter.</b> The OAEP hash is read from the container's header, so a reader
    /// cannot be pointed at the wrong one — and an edited hash byte simply names a hash the wrap did not
    /// use, which surfaces as the unwrap failure it is.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="privateKeyPem"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="privateKeyPem"/> is empty, or is not a readable RSA private-key PEM. A PEM that cannot be parsed is a credential-supply error and propagates from Enigma.Core unwrapped, as <see cref="ArgumentException"/> — including where its Base64 is invalid, a case Enigma.Core 1.1.0 no longer surfaces as a bare <see cref="FormatException"/> but preserves as an inner exception. <c>docs/format.md</c> §9 permits either type.</exception>
    /// <exception cref="DataEncryptionFormatException">The header is not a valid RSA container, its OAEP-hash byte is undefined or the reserved SHA-1 value, the wrapped-key length is out of bounds, or the wrapped key does not hold a 32-byte data key.</exception>
    /// <exception cref="DataDecryptionException">The private key does not open the container — an OAEP unwrap failure (which is also how an encrypted PEM supplied with the wrong or no passphrase surfaces, the underlying exception kept as <see cref="System.Exception.InnerException"/>) or a key-confirmation mismatch — or the payload fails authentication.</exception>
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
