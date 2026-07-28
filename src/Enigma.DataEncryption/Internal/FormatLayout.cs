namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The container format's fixed wire layout: the magic bytes and the five header lengths of
/// <c>docs/format.md</c> §3.
/// </summary>
/// <remarks>
/// The lengths are <b>computed</b> from <see cref="DataEncryptionDefaults"/> rather than written as
/// literals, so a field size cannot move without every length moving with it.
/// <c>FormatConstantsTests</c> and <c>FormatLayoutTests</c> pin the resulting numbers
/// (53 / 61 / 38 + N / 38 + N / 42 + N + M) against the specification, which is what keeps this
/// arithmetic honest.
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

    /// <summary>Length of method <c>0x03</c>'s RSA-OAEP hash byte, in bytes.</summary>
    /// <remarks>
    /// The same size as <see cref="ParameterSetLength"/>, at the same offset 5, and deliberately
    /// <b>not</b> the same constant: the two fields belong to different methods and mean different
    /// things, so each header shape's arithmetic must still read on its own. See
    /// <c>docs/format.md</c> §3.3.
    /// </remarks>
    internal const int OaepHashLength = 1;

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
    /// RSA header length <b>excluding</b> the wrapped key: prefix + OAEP hash + nonce + length field +
    /// tag. 38 bytes; the total is this plus the wrapped-key length.
    /// </summary>
    /// <remarks>
    /// Equal to <see cref="MLKemHeaderBaseLength"/>, and not by coincidence: both methods put a
    /// one-byte algorithm selector at offset 5, so the two public-key shapes are structurally
    /// identical. See <c>docs/format.md</c> §3.3.
    /// </remarks>
    internal const int RsaHeaderBaseLength =
        CommonPrefixLength
        + OaepHashLength
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

    /// <summary>
    /// Hybrid header length <b>excluding</b> both variable-length fields: prefix + parameter set +
    /// nonce + two length fields + tag. 42 bytes; the total is this plus the wrapped-secret length
    /// <c>N</c> plus the encapsulation length <c>M</c>.
    /// </summary>
    /// <remarks>
    /// Four bytes longer than <see cref="MLKemHeaderBaseLength"/>, and the difference is the second
    /// <see cref="Int32Length"/> length field — the hybrid carries two variable-length fields where
    /// every other method carries at most one. See <c>docs/format.md</c> §3.5.
    /// </remarks>
    internal const int HybridHeaderBaseLength =
        CommonPrefixLength
        + ParameterSetLength
        + DataEncryptionDefaults.NonceSizeBytes
        + (2 * Int32Length)
        + DataEncryptionDefaults.KeyConfirmationTagSizeBytes;

    /// <summary>
    /// Offset of the hybrid header's encapsulation length field, given the wrapped-secret length.
    /// </summary>
    /// <param name="wrappedSecretLength">The wrapped-secret length <c>N</c>.</param>
    /// <returns><c>22 + N</c>.</returns>
    /// <remarks>
    /// Exists so that the key combiner's transcript (<c>docs/format.md</c> §3.5.1) can be described, and
    /// asserted, as the contiguous header slice it is.
    /// </remarks>
    internal static int HybridEncapsulationLengthOffset(int wrappedSecretLength) =>
        HybridWrappedSecretLengthOffset + Int32Length + wrappedSecretLength;

    /// <summary>Offset of the hybrid header's wrapped-secret length field: 18.</summary>
    internal const int HybridWrappedSecretLengthOffset =
        CommonPrefixLength + ParameterSetLength + DataEncryptionDefaults.NonceSizeBytes;
}
