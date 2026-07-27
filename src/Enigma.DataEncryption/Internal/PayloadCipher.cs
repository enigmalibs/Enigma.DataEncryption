using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The payload stage every method shares: one AEAD operation in GCM mode, with the complete header as
/// associated data.
/// </summary>
/// <remarks>
/// <para>
/// The four fixed GCM parameters of <c>docs/format.md</c> §4 — mode, padding, tag size and
/// "associated data is the header" — are applied here rather than at each of the four call sites, so
/// they cannot drift apart between methods. The cipher is resolved through
/// <see cref="CipherResolver"/>; everything else is invariant.
/// </para>
/// <para>
/// <b>Decryption translates the AEAD failure and encryption does not.</b> A GCM authentication
/// failure — a tampered payload, an edited header, or a wrong key that got past key confirmation —
/// reaches us as <see cref="CryptographicException"/> and becomes
/// <see cref="DataDecryptionException"/> (§9). Encryption has no equivalent: there is nothing to
/// authenticate against, so nothing is caught and no exception is reshaped.
/// </para>
/// <para>Neither stream is disposed, and progress is forwarded untouched — it counts payload bytes only.</para>
/// </remarks>
internal static class PayloadCipher
{
    /// <summary>Encrypts the payload into the container, authenticating the header alongside it.</summary>
    /// <param name="blockCipherServiceFactory">Supplies the block cipher selected by <paramref name="cipher"/>.</param>
    /// <param name="cipher">The payload cipher, already validated.</param>
    /// <param name="input">The plaintext stream, read to its end.</param>
    /// <param name="output">The container stream, positioned just after the header.</param>
    /// <param name="dataKey">The 32-byte data key.</param>
    /// <param name="nonce">The 12-byte GCM nonce, as written into the header.</param>
    /// <param name="header">The complete header — the associated data.</param>
    /// <param name="progress">Optional receiver of payload-byte progress.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption.</returns>
    internal static Task EncryptAsync(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        Cipher cipher,
        Stream input,
        Stream output,
        byte[] dataKey,
        byte[] nonce,
        byte[] header,
        IProgress<int>? progress,
        CancellationToken cancellationToken) =>
        CipherResolver.Resolve(blockCipherServiceFactory, cipher).EncryptAsync(
            input,
            output,
            dataKey,
            nonce,
            BlockCipherMode.Gcm,
            PaddingScheme.None,
            DataEncryptionDefaults.GcmMacSizeBits,
            header,
            progress,
            cancellationToken);

    /// <summary>Decrypts the payload, verifying the header along with it.</summary>
    /// <param name="blockCipherServiceFactory">Supplies the block cipher selected by <paramref name="cipher"/>.</param>
    /// <param name="cipher">The payload cipher, as read from the header.</param>
    /// <param name="input">The container stream, positioned at the first payload byte.</param>
    /// <param name="output">The stream the recovered plaintext is written to.</param>
    /// <param name="dataKey">The 32-byte data key, as just derived or recovered.</param>
    /// <param name="nonce">The 12-byte GCM nonce, as read from the header.</param>
    /// <param name="header">The complete header exactly as read — the associated data.</param>
    /// <param name="progress">Optional receiver of payload-byte progress.</param>
    /// <param name="cancellationToken">Token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption.</returns>
    /// <exception cref="DataDecryptionException">
    /// The payload or the header failed authentication — the container was truncated or edited, or the
    /// key is wrong.
    /// </exception>
    internal static async Task DecryptAsync(
        IBlockCipherServiceFactory blockCipherServiceFactory,
        Cipher cipher,
        Stream input,
        Stream output,
        byte[] dataKey,
        byte[] nonce,
        byte[] header,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        try
        {
            await CipherResolver.Resolve(blockCipherServiceFactory, cipher).DecryptAsync(
                input,
                output,
                dataKey,
                nonce,
                BlockCipherMode.Gcm,
                PaddingScheme.None,
                DataEncryptionDefaults.GcmMacSizeBits,
                header,
                progress,
                cancellationToken).ConfigureAwait(false);
        }
        catch (CryptographicException exception)
        {
            throw new DataDecryptionException(
                "The container failed authentication: the payload or the header has been altered, or the container is truncated.",
                exception);
        }
    }
}
