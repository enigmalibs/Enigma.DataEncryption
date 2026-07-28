namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The container format's fixed wire layout: the magic bytes and the four header lengths of
/// <c>docs/format.md</c> §3.
/// </summary>
/// <remarks>
/// The lengths are <b>computed</b> from <see cref="DataEncryptionDefaults"/> rather than written as
/// literals, so a field size cannot move without every length moving with it.
/// <c>FormatConstantsTests</c> and <c>HeaderLayoutTests</c> pin the resulting numbers
/// (53 / 61 / 37 + N / 38 + N) against the specification, which is what keeps this arithmetic honest.
/// </remarks>
internal static class FormatLayout
{
    /// <summary>The first magic byte, at offset 0: <c>0xEC</c>.</summary>
    internal const byte MagicByte0 = 0xEC;

    /// <summary>The second magic byte, at offset 1: <c>0xDE</c>.</summary>
    internal const byte MagicByte1 = 0xDE;

    /// <summary>Length of the magic, in bytes.</summary>
    internal const int MagicLength = 2;

    /// <summary>Length of a signed 32-bit little-endian integer on the wire, in bytes.</summary>
    internal const int Int32Length = 4;

    /// <summary>Length of the ML-KEM parameter-set byte, in bytes.</summary>
    internal const int ParameterSetLength = 1;

    /// <summary>
    /// Length of the prefix every method shares: magic (2) + method (1) + version (1) + cipher (1).
    /// </summary>
    internal const int CommonPrefixLength = MagicLength + 1 + 1 + 1;

    /// <summary>Total PBKDF2 header length: prefix + nonce + salt + iterations + tag. 53 bytes.</summary>
    internal const int Pbkdf2HeaderLength =
        CommonPrefixLength
        + DataEncryptionDefaults.NonceSizeBytes
        + DataEncryptionDefaults.SaltSizeBytes
        + Int32Length
        + DataEncryptionDefaults.KeyConfirmationTagSizeBytes;

    /// <summary>
    /// Total Argon2 header length: prefix + nonce + salt + iterations + parallelism + memory + tag.
    /// 61 bytes.
    /// </summary>
    internal const int Argon2HeaderLength =
        CommonPrefixLength
        + DataEncryptionDefaults.NonceSizeBytes
        + DataEncryptionDefaults.SaltSizeBytes
        + (3 * Int32Length)
        + DataEncryptionDefaults.KeyConfirmationTagSizeBytes;

    /// <summary>
    /// RSA header length <b>excluding</b> the wrapped key: prefix + nonce + length field + tag.
    /// 37 bytes; the total is this plus the wrapped-key length.
    /// </summary>
    internal const int RsaHeaderBaseLength =
        CommonPrefixLength
        + DataEncryptionDefaults.NonceSizeBytes
        + Int32Length
        + DataEncryptionDefaults.KeyConfirmationTagSizeBytes;

    /// <summary>
    /// ML-KEM header length <b>excluding</b> the encapsulation: prefix + parameter set + nonce +
    /// length field + tag. 38 bytes; the total is this plus the encapsulation length.
    /// </summary>
    internal const int MLKemHeaderBaseLength =
        CommonPrefixLength
        + ParameterSetLength
        + DataEncryptionDefaults.NonceSizeBytes
        + Int32Length
        + DataEncryptionDefaults.KeyConfirmationTagSizeBytes;
}
