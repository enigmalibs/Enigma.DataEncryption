using System;
using Enigma.Core.Asymmetric.Pqc;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Everything <see cref="HeaderReader"/> recovers from a container header: the public
/// <see cref="EncryptedDataHeader"/> the inspector returns, the raw bytes that form the GCM associated
/// data, and the method-specific material a decryption service needs.
/// </summary>
/// <remarks>
/// This type exists because <see cref="EncryptedDataHeader"/> deliberately withholds the salt, nonce,
/// wrapped key, encapsulation and confirmation tag from public callers — but the services do need
/// them. Keeping the public record free of that material and carrying it on this internal type is what
/// lets both be true at once.
/// </remarks>
internal sealed record ParsedHeader
{
    /// <summary>The parsed header as the public API reports it.</summary>
    internal required EncryptedDataHeader Header { get; init; }

    /// <summary>
    /// The complete header exactly as read from the stream, including the key-confirmation tag. This is
    /// the GCM associated data; it is the bytes that were <b>consumed</b>, never a re-serialization of
    /// the parsed fields.
    /// </summary>
    internal required byte[] HeaderBytes { get; init; }

    /// <summary>The 12-byte GCM nonce.</summary>
    internal required byte[] Nonce { get; init; }

    /// <summary>The 16-byte key-confirmation tag that closes the header.</summary>
    internal required byte[] KeyConfirmationTag { get; init; }

    /// <summary>
    /// The bytes of <see cref="HeaderBytes"/> that precede the key-confirmation tag — the message the
    /// tag is computed over (<c>docs/format.md</c> §6).
    /// </summary>
    internal byte[] BytesBeforeTag
    {
        get
        {
            int length = HeaderBytes.Length - DataEncryptionDefaults.KeyConfirmationTagSizeBytes;
            byte[] bytes = new byte[length];
            Buffer.BlockCopy(HeaderBytes, 0, bytes, 0, length);
            return bytes;
        }
    }

    /// <summary>The 16-byte KDF salt. Populated for PBKDF2 and Argon2 only.</summary>
    internal byte[]? Salt { get; init; }

    /// <summary>The RSAES-OAEP-wrapped data key. Populated for RSA only.</summary>
    internal byte[]? WrappedKey { get; init; }

    /// <summary>The ML-KEM encapsulation. Populated for ML-KEM only.</summary>
    internal byte[]? Encapsulation { get; init; }

    /// <summary>The ML-KEM parameter set from header offset 5. Populated for ML-KEM only.</summary>
    internal MLKemParameterSet? MLKemParameterSet { get; init; }
}
