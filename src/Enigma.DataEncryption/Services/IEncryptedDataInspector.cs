using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.DataEncryption;

/// <summary>
/// Reads a container's plaintext header <b>without decrypting it</b> and without any credential.
/// </summary>
/// <remarks>
/// <para>
/// Use it to answer the questions a caller has before it can even ask for a credential: which method
/// produced this container, which cipher protects it, how costly the derivation will be, and where
/// the payload starts.
/// </para>
/// <para>
/// Nothing secret is exposed: the returned <see cref="EncryptedDataHeader"/> deliberately omits the
/// salt, the nonce, the wrapped key, the encapsulation and the key-confirmation tag.
/// </para>
/// <para>Implementations are stateless and safe for concurrent use.</para>
/// </remarks>
public interface IEncryptedDataInspector
{
    /// <summary>
    /// Reads and validates the header at the current position of <paramref name="input"/>.
    /// </summary>
    /// <param name="input">
    /// The container stream, positioned at the magic. It need not be seekable.
    /// </param>
    /// <param name="limits">
    /// Bounds applied to the header's cost and length fields, exactly as during decryption. Pass
    /// <see langword="null"/> to use <see cref="DataEncryptionLimits.Default"/>.
    /// </param>
    /// <param name="cancellationToken">Optional token to cancel the operation.</param>
    /// <returns>A task whose result is the parsed header.</returns>
    /// <remarks>
    /// <para>
    /// <b>Stream position.</b> Reading the header consumes it. <b>If <paramref name="input"/> is
    /// seekable, the original position is restored before returning</b>, so the stream can be handed
    /// straight to a decryption service. <b>If it is not seekable, the stream is left positioned at
    /// the first payload byte</b> and the header cannot be re-read — a caller that needs both the
    /// header and a subsequent decrypt must buffer the stream itself.
    /// </para>
    /// <para>
    /// The stream is never disposed. No credential is used and no payload byte is read, so this
    /// method cannot fail with <see cref="DataDecryptionException"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="input"/> is <see langword="null"/>.</exception>
    /// <exception cref="DataEncryptionFormatException">The header is not a valid format-<c>0x10</c> container, the stream ends inside it, or a cost or length field is out of bounds.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task<EncryptedDataHeader> ReadHeaderAsync(
        Stream input,
        DataEncryptionLimits? limits = null,
        CancellationToken cancellationToken = default);
}
