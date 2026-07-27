using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;

namespace Enigma.DataEncryption;

/// <summary>
/// Encrypts and decrypts data with an <b>ML-KEM</b> (FIPS 203) key pair, using the encapsulated
/// 32-byte shared secret directly as the data key (container method <c>0x04</c>).
/// </summary>
/// <remarks>
/// <para>
/// Produces a self-describing container: a (38 + <c>N</c>)-byte plaintext header — magic, method,
/// version, cipher, parameter set, GCM nonce, encapsulation length <c>N</c>, the encapsulation,
/// key-confirmation tag — followed by the AEAD payload. The complete header is passed as GCM
/// associated data, so any header edit is an authentication failure. See <c>docs/format.md</c> §3.4.
/// </para>
/// <para>
/// <b>No additional key-derivation step is applied to the shared secret.</b> FIPS 203 shared secrets
/// are uniformly random 32-byte values — exactly what a 256-bit data key needs — and the context
/// binding a KDF would normally provide is already achieved by passing the complete header as
/// associated data.
/// </para>
/// <para>
/// FIPS 203 <i>implicit rejection</i> means decapsulation with a wrong private key succeeds, returning
/// a wrong-but-well-formed secret. The key-confirmation tag is what turns that into a clean error
/// before any payload byte is read.
/// </para>
/// <para>
/// Keys are raw FIPS 203 byte encodings, interchangeable with
/// <c>Enigma.Core.Asymmetric.Pqc.IMLKemService.GenerateKeyPair</c>.
/// </para>
/// <para>Implementations are stateless and safe for concurrent use.</para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public interface IMLKemDataEncryptionService
{
    /// <summary>
    /// Encrypts <paramref name="input"/> into <paramref name="output"/> for the holder of the private
    /// key matching <paramref name="publicKey"/>.
    /// </summary>
    /// <param name="input">The plaintext stream, read to its end.</param>
    /// <param name="output">The stream the container is written to — header first, then payload.</param>
    /// <param name="cipher">The AEAD block cipher to protect the payload with.</param>
    /// <param name="publicKey">
    /// The recipient's ML-KEM public (encapsulation) key, in its raw FIPS 203 encoding. Its length
    /// must match <paramref name="parameterSet"/>.
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
    /// Neither stream is disposed, and both are left wherever the operation ended. The shared secret
    /// and the key-confirmation key are cleared before returning; the caller-supplied
    /// <paramref name="publicKey"/> is not.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="publicKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="publicKey"/> is empty or the wrong length for <paramref name="parameterSet"/>, or <paramref name="cipher"/> / <paramref name="parameterSet"/> is not a defined value.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task EncryptAsync(
        Stream input,
        Stream output,
        Cipher cipher,
        byte[] publicKey,
        MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts an ML-KEM container from <paramref name="input"/> into <paramref name="output"/>.
    /// </summary>
    /// <param name="input">
    /// The container stream, positioned at the magic. <b>It need not be seekable</b> — the header is
    /// read forward, once, and the payload is streamed from wherever it ended.
    /// </param>
    /// <param name="output">The stream the recovered plaintext is written to.</param>
    /// <param name="privateKey">
    /// The recipient's ML-KEM private (decapsulation) key, in its raw expanded FIPS 203 encoding. The
    /// array is neither mutated nor cleared: the caller owns its lifetime.
    /// </param>
    /// <param name="limits">
    /// Bounds applied to the header's encapsulation length before it is allocated or read. Pass
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
    /// Neither stream is disposed, and both are left wherever the operation ended. The decapsulated
    /// shared secret and the key-confirmation key are cleared before returning; the caller-supplied
    /// <paramref name="privateKey"/> is not.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/>, <paramref name="output"/> or <paramref name="privateKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="privateKey"/> is empty or the wrong length for the header's parameter set.</exception>
    /// <exception cref="DataEncryptionFormatException">The header is not a valid ML-KEM container, its parameter-set byte is undefined, or the encapsulation length is out of bounds.</exception>
    /// <exception cref="DataDecryptionException">The private key does not match the container (key-confirmation mismatch), or the payload fails authentication.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] privateKey,
        DataEncryptionLimits? limits = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
