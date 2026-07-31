using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;

namespace Enigma.DataEncryption;

/// <summary>
/// Encrypts and decrypts data under an <b>RSA key pair and an ML-KEM (FIPS 203) key pair together</b>,
/// combining a secret transported by each into the data key, so that breaking one primitive is not
/// enough to open the container (container method <c>0x05</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Both credentials are required in both directions.</b> Holding only the RSA private key, or only the
/// ML-KEM private key, is worth nothing — that is the entire point of the method, and the reason every
/// operation below takes two keys rather than one.
/// </para>
/// <para>
/// Produces a self-describing container: a (42 + <c>N</c> + <c>M</c>)-byte plaintext header — magic,
/// method, version, cipher, parameter set, GCM nonce, wrapped-secret length <c>N</c>, the RSAES-OAEP
/// ciphertext, encapsulation length <c>M</c>, the ML-KEM encapsulation, key-confirmation tag — followed by
/// the AEAD payload. The complete header is passed as GCM associated data, so any header edit is an
/// authentication failure. See <c>docs/format.md</c> §3.5.
/// </para>
/// <para>
/// <b>Why hybrid.</b> An RSA-only container falls to a sufficiently large quantum computer; an
/// ML-KEM-only container falls to a classical cryptanalytic break of ML-KEM. This method wraps a random
/// 32-byte secret under the RSA public key, encapsulates a second secret against the ML-KEM public key,
/// and derives the data key from <i>both</i> — so the container stays secure as long as <b>either</b>
/// primitive holds. That is what post-quantum migration guidance recommends for the transition period,
/// and it is the strongest option this library offers.
/// </para>
/// <para>
/// <b>The combiner.</b> The data key is
/// <c>HMAC-SHA256(rsaSecret, "…/hybrid/rsa/v1" ‖ T) XOR HMAC-SHA256(kemSecret, "…/hybrid/mlkem/v1" ‖ T)</c>,
/// where <c>T</c> binds both ciphertexts. Each secret keys its own HMAC, which is what makes the result a
/// <i>split-key PRF</i> — good if either key is — and the two labels differ so that two equal secrets
/// cannot cancel. <c>docs/format.md</c> §3.5.1 specifies it and §3.5.2 states the rationale; this is not
/// an XOR of the two secrets, which would not have that property.
/// </para>
/// <para>
/// <b>How a wrong credential surfaces differs by half.</b> A wrong RSA private key is caught by the OAEP
/// unwrap; a wrong ML-KEM private key is not caught there at all, because FIPS 203 implicit rejection
/// makes decapsulation with a wrong key <i>succeed</i> — the key-confirmation tag is what catches it,
/// before any payload byte is read. Either way the caller sees
/// <see cref="DataDecryptionException"/>.
/// </para>
/// <para>
/// RSA keys are PEM strings, as for <see cref="IRsaDataEncryptionService"/>; ML-KEM keys are raw FIPS 203
/// byte encodings, as for <see cref="IMLKemDataEncryptionService"/>. Both are interchangeable with
/// Enigma.Core's <c>IPublicKeyService.GenerateRsaKeyPair</c> and <c>IMLKemService.GenerateKeyPair</c>.
/// </para>
/// <para>
/// <b>One wrinkle worth knowing about the RSA parameters' names.</b> A PEM this library cannot parse is
/// reported by Enigma.Core and propagates unwrapped (<c>docs/format.md</c> §9), so the
/// <see cref="ArgumentException.ParamName"/> in that case is Enigma.Core's <c>publicKeyPem</c> or
/// <c>privateKeyPem</c> rather than this method's <c>rsaPublicKeyPem</c> or <c>rsaPrivateKeyPem</c>. A
/// <see langword="null"/> or empty PEM is rejected by this library and does carry the parameter's own
/// name. Correcting the former would mean catching and re-throwing, which is exactly the wrapping §9 rules
/// out for a credential-supply error — so the discrepancy is documented rather than hidden.
/// </para>
/// <para>Implementations are stateless and safe for concurrent use.</para>
/// </remarks>
public interface IHybridDataEncryptionService
{
    /// <summary>
    /// Encrypts <paramref name="input"/> into <paramref name="output"/> for the holder of <b>both</b>
    /// private keys matching <paramref name="rsaPublicKeyPem"/> and <paramref name="mlKemPublicKey"/>.
    /// </summary>
    /// <param name="input">The plaintext stream, read to its end.</param>
    /// <param name="output">The stream the container is written to — header first, then payload.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="rsaPublicKeyPem">The recipient's RSA public key, PEM-encoded.</param>
    /// <param name="mlKemPublicKey">
    /// The recipient's ML-KEM public (encapsulation) key, in its raw FIPS 203 encoding. Its length must
    /// match <paramref name="parameterSet"/>.
    /// </param>
    /// <param name="parameterSet">
    /// The ML-KEM parameter set to encapsulate under, written into the header so the reader needs no
    /// out-of-band knowledge. Defaults to <see cref="MLKemParameterSet.MLKem1024"/>.
    /// </param>
    /// <param name="progress">
    /// Optional progress receiver, reporting <b>payload bytes processed</b>. Header bytes are not
    /// counted.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    /// <remarks>
    /// <para>
    /// Both public-key operations happen <b>before</b> anything is written, so a key this library cannot
    /// use leaves the output stream untouched.
    /// </para>
    /// <para>
    /// Neither stream is disposed, and both are left wherever the operation ended. The two transported
    /// secrets, the combined data key and the key-confirmation key are all cleared before returning; the
    /// caller-supplied keys are not.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/>, <paramref name="rsaPublicKeyPem"/> or <paramref name="mlKemPublicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="rsaPublicKeyPem"/> or <paramref name="mlKemPublicKey"/> is empty; <paramref name="rsaPublicKeyPem"/> is not a readable RSA public-key PEM; <paramref name="mlKemPublicKey"/> is malformed or the wrong length for <paramref name="parameterSet"/>; or <paramref name="cipher"/> / <paramref name="parameterSet"/> is not a defined value.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        string rsaPublicKeyPem,
        byte[] mlKemPublicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a hybrid container from <paramref name="input"/> into <paramref name="output"/>, using
    /// <b>both</b> private keys.
    /// </summary>
    /// <param name="input">
    /// The container stream, positioned at the magic. <b>It need not be seekable</b> — the header is
    /// read forward, once, and the payload is streamed from wherever it ended.
    /// </param>
    /// <param name="output">The stream the recovered plaintext is written to.</param>
    /// <param name="rsaPrivateKeyPem">
    /// The recipient's RSA private key, PEM-encoded; may be an encrypted private-key PEM, in which case
    /// supply <paramref name="rsaKeyPassword"/>.
    /// </param>
    /// <param name="mlKemPrivateKey">
    /// The recipient's ML-KEM private (decapsulation) key, in its raw expanded FIPS 203 encoding. The
    /// array is neither mutated nor cleared: the caller owns its lifetime.
    /// </param>
    /// <param name="rsaKeyPassword">
    /// The passphrase protecting an encrypted <paramref name="rsaPrivateKeyPem"/>, or
    /// <see langword="null"/> if it is unencrypted. Never cleared by this method.
    /// </param>
    /// <param name="limits">
    /// Bounds applied to the header's two length fields before either buffer is allocated or read. Pass
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
    /// <b>The parameter set is read from the header</b> and is deliberately not a parameter here — the
    /// container already records which one it was encapsulated under, and accepting a second opinion
    /// could only introduce a mismatch.
    /// </para>
    /// <para>
    /// The bounds applied to the two length fields are <see cref="DataEncryptionLimits.MaxWrappedKeyLength"/>
    /// and <see cref="DataEncryptionLimits.MaxEncapsulationLength"/> — the same two the RSA and ML-KEM
    /// methods use, because they bound the same two quantities.
    /// </para>
    /// <para>
    /// Neither stream is disposed, and both are left wherever the operation ended. Both recovered
    /// secrets, the combined data key and the key-confirmation key are cleared before returning — the
    /// secrets a <i>wrong</i> credential produces included; the caller-supplied keys are not.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/>, <paramref name="rsaPrivateKeyPem"/> or <paramref name="mlKemPrivateKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="rsaPrivateKeyPem"/> or <paramref name="mlKemPrivateKey"/> is empty, or <paramref name="rsaPrivateKeyPem"/> cannot be parsed as an RSA private-key PEM.</exception>
    /// <exception cref="DataEncryptionFormatException">The header is not a valid hybrid container, its parameter-set byte is undefined, a length field is out of bounds, or the RSAES-OAEP ciphertext unwraps to something other than 32 bytes.</exception>
    /// <exception cref="DataDecryptionException">
    /// Either private key is wrong, the payload fails authentication, or a secret could not be recovered
    /// at all. The RSA unwrap runs first, so when both keys are wrong it is the RSA failure that is
    /// reported; a wrong ML-KEM key reaches the key-confirmation tag instead, because implicit rejection
    /// lets its decapsulation succeed. An <paramref name="mlKemPrivateKey"/> that is malformed or for
    /// another parameter set, and an undecryptable <paramref name="rsaPrivateKeyPem"/>, are <b>not</b>
    /// separated into argument errors, for the reasons <c>docs/format.md</c> §9 gives; the original
    /// exception is preserved as <see cref="System.Exception.InnerException"/>.
    /// </exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task DecryptAsync(
        Stream input,
        Stream output,
        string rsaPrivateKeyPem,
        byte[] mlKemPrivateKey,
        char[]? rsaKeyPassword = null,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
