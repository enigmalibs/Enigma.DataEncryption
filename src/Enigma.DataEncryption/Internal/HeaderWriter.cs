using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Extensions;
using Enigma.Core.Hashing.Hmac;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Builds a container header in memory, seals it with the key-confirmation tag, writes it to the
/// output stream and hands the exact bytes written back to the caller — which are the bytes the GCM
/// operation must pass as its associated data.
/// </summary>
/// <remarks>
/// <para>
/// The header <b>is</b> the AAD (<c>docs/format.md</c> §5), so materializing it in memory is required
/// regardless. Building it, tagging it, writing it and returning it from one place makes
/// "the AAD is exactly what was written" structurally true rather than something the four services
/// each have to remember.
/// </para>
/// <para>
/// The ordering matters and is not circular: the tag is computed over the header bytes that
/// <b>precede</b> it, and the AAD is the header <b>including</b> the tag (§5).
/// </para>
/// </remarks>
internal static class HeaderWriter
{
    /// <summary>Writes a PBKDF2 (method <c>0x01</c>) header. 53 bytes.</summary>
    /// <param name="output">The container stream, positioned where the header begins.</param>
    /// <param name="cipher">The payload cipher, already validated.</param>
    /// <param name="nonce">The 12-byte GCM nonce.</param>
    /// <param name="salt">The 16-byte PBKDF2 salt.</param>
    /// <param name="iterations">The PBKDF2 iteration count.</param>
    /// <param name="dataKey">The 32-byte data key, used to compute the key-confirmation tag.</param>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="cancellationToken">Token to cancel the write.</param>
    /// <returns>The complete header bytes, to be passed as the GCM associated data.</returns>
    internal static async Task<byte[]> WritePbkdf2HeaderAsync(
        Stream output,
        Cipher cipher,
        byte[] nonce,
        byte[] salt,
        int iterations,
        byte[] dataKey,
        IHmacService hmacSha256,
        CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new(FormatLayout.Pbkdf2HeaderLength);
        WriteCommonPrefix(buffer, EncryptionMethod.Pbkdf2, cipher);
        buffer.WriteBytes(nonce);
        buffer.WriteBytes(salt);
        buffer.WriteInt(iterations);

        return await SealAndWriteAsync(output, buffer, dataKey, hmacSha256, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Writes an Argon2 (method <c>0x02</c>) header. 61 bytes.</summary>
    /// <param name="output">The container stream, positioned where the header begins.</param>
    /// <param name="cipher">The payload cipher, already validated.</param>
    /// <param name="nonce">The 12-byte GCM nonce.</param>
    /// <param name="salt">The 16-byte Argon2 salt.</param>
    /// <param name="iterations">The Argon2 iteration count (passes over memory).</param>
    /// <param name="degreeOfParallelism">The Argon2 degree of parallelism.</param>
    /// <param name="memorySizeKb">The Argon2 memory cost in kibibytes.</param>
    /// <param name="dataKey">The 32-byte data key, used to compute the key-confirmation tag.</param>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="cancellationToken">Token to cancel the write.</param>
    /// <returns>The complete header bytes, to be passed as the GCM associated data.</returns>
    /// <remarks>
    /// Parallelism is written <b>before</b> memory, and memory is the KiB value itself rather than the
    /// predecessor library's power-of-two exponent — see <c>docs/format.md</c> §3.2.
    /// </remarks>
    internal static async Task<byte[]> WriteArgon2HeaderAsync(
        Stream output,
        Cipher cipher,
        byte[] nonce,
        byte[] salt,
        int iterations,
        int degreeOfParallelism,
        int memorySizeKb,
        byte[] dataKey,
        IHmacService hmacSha256,
        CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new(FormatLayout.Argon2HeaderLength);
        WriteCommonPrefix(buffer, EncryptionMethod.Argon2, cipher);
        buffer.WriteBytes(nonce);
        buffer.WriteBytes(salt);
        buffer.WriteInt(iterations);
        buffer.WriteInt(degreeOfParallelism);
        buffer.WriteInt(memorySizeKb);

        return await SealAndWriteAsync(output, buffer, dataKey, hmacSha256, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Writes an RSA (method <c>0x03</c>) header. 37 + <c>N</c> bytes.</summary>
    /// <param name="output">The container stream, positioned where the header begins.</param>
    /// <param name="cipher">The payload cipher, already validated.</param>
    /// <param name="nonce">The 12-byte GCM nonce.</param>
    /// <param name="wrappedKey">The RSAES-OAEP-wrapped data key; its length becomes <c>N</c>.</param>
    /// <param name="dataKey">The 32-byte data key, used to compute the key-confirmation tag.</param>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="cancellationToken">Token to cancel the write.</param>
    /// <returns>The complete header bytes, to be passed as the GCM associated data.</returns>
    internal static async Task<byte[]> WriteRsaHeaderAsync(
        Stream output,
        Cipher cipher,
        byte[] nonce,
        byte[] wrappedKey,
        byte[] dataKey,
        IHmacService hmacSha256,
        CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new(FormatLayout.RsaHeaderBaseLength + wrappedKey.Length);
        WriteCommonPrefix(buffer, EncryptionMethod.Rsa, cipher);
        buffer.WriteBytes(nonce);
        buffer.WriteInt(wrappedKey.Length);
        buffer.WriteBytes(wrappedKey);

        return await SealAndWriteAsync(output, buffer, dataKey, hmacSha256, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Writes an ML-KEM (method <c>0x04</c>) header. 38 + <c>N</c> bytes.</summary>
    /// <param name="output">The container stream, positioned where the header begins.</param>
    /// <param name="cipher">The payload cipher, already validated.</param>
    /// <param name="parameterSet">The ML-KEM parameter set the encapsulation was produced under.</param>
    /// <param name="nonce">The 12-byte GCM nonce.</param>
    /// <param name="encapsulation">The ML-KEM encapsulation; its length becomes <c>N</c>.</param>
    /// <param name="dataKey">The 32-byte shared secret, used to compute the key-confirmation tag.</param>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="cancellationToken">Token to cancel the write.</param>
    /// <returns>The complete header bytes, to be passed as the GCM associated data.</returns>
    /// <remarks>The parameter-set byte precedes the nonce — see <c>docs/format.md</c> §3.4.</remarks>
    internal static async Task<byte[]> WriteMLKemHeaderAsync(
        Stream output,
        Cipher cipher,
        MLKemParameterSet parameterSet,
        byte[] nonce,
        byte[] encapsulation,
        byte[] dataKey,
        IHmacService hmacSha256,
        CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new(FormatLayout.MLKemHeaderBaseLength + encapsulation.Length);
        WriteCommonPrefix(buffer, EncryptionMethod.MLKem, cipher);
        buffer.WriteByte(MLKemParameterSetWire.ToWireByte(parameterSet));
        buffer.WriteBytes(nonce);
        buffer.WriteInt(encapsulation.Length);
        buffer.WriteBytes(encapsulation);

        return await SealAndWriteAsync(output, buffer, dataKey, hmacSha256, cancellationToken)
            .ConfigureAwait(false);
    }

    private static void WriteCommonPrefix(Stream buffer, EncryptionMethod method, Cipher cipher)
    {
        buffer.WriteByte(FormatLayout.MagicByte0);
        buffer.WriteByte(FormatLayout.MagicByte1);
        buffer.WriteByte((byte)method);
        buffer.WriteByte(DataEncryptionDefaults.FormatVersion);
        buffer.WriteByte((byte)cipher);
    }

    private static async Task<byte[]> SealAndWriteAsync(
        Stream output,
        MemoryStream buffer,
        byte[] dataKey,
        IHmacService hmacSha256,
        CancellationToken cancellationToken)
    {
        byte[] beforeTag = buffer.ToArray();
        byte[] tag = KeyConfirmation.ComputeTag(hmacSha256, dataKey, beforeTag);

        byte[] header = new byte[beforeTag.Length + tag.Length];
        Buffer.BlockCopy(beforeTag, 0, header, 0, beforeTag.Length);
        Buffer.BlockCopy(tag, 0, header, beforeTag.Length, tag.Length);

        await output.WriteBytesAsync(header, cancellationToken).ConfigureAwait(false);
        return header;
    }
}
