using System;
using Enigma.Core.Asymmetric.PublicKey;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Translates between Enigma.Core's <see cref="RsaOaepHash"/> and method <c>0x03</c>'s OAEP-hash byte
/// at offset 5.
/// </summary>
/// <remarks>
/// <para>
/// <b>The wire byte is not the enum's numeric value.</b> <see cref="RsaOaepHash"/> is a plain unnumbered
/// C# enum, so its members are <c>0</c> through <c>3</c>; the wire bytes are <c>0x01</c> through
/// <c>0x04</c>, deliberately 1-based so that <c>0x00</c> is never valid and a zero-filled header cannot
/// parse. Mapping must therefore be explicit — a cast would silently shift every value by one. This is
/// the same rule <see cref="MLKemParameterSetWire"/> carries for the field that shares this offset. See
/// <c>docs/format.md</c> §3.3.
/// </para>
/// <para>
/// <b><see cref="RsaOaepHash.Sha1"/> is numbered but not accepted.</b> Its byte <c>0x01</c> is reserved
/// (§10): no writer may emit it and the reader rejects it. Numbering it anyway — rather than renumbering
/// the accepted set to start at <c>0x01</c> — is what keeps enabling SHA-1 later a pure un-reservation.
/// </para>
/// </remarks>
internal static class RsaOaepHashWire
{
    /// <summary>
    /// The header byte <b>reserved</b> for OAEP-SHA-1. Never written, always rejected on read.
    /// </summary>
    internal const byte Sha1Byte = 0x01;

    /// <summary>The header byte denoting OAEP-SHA-256 — the default.</summary>
    internal const byte Sha256Byte = 0x02;

    /// <summary>The header byte denoting OAEP-SHA-384.</summary>
    internal const byte Sha384Byte = 0x03;

    /// <summary>The header byte denoting OAEP-SHA-512.</summary>
    internal const byte Sha512Byte = 0x04;

    /// <summary>Maps an OAEP hash to its header byte.</summary>
    /// <param name="oaepHash">The hash supplied by the caller.</param>
    /// <returns>The corresponding header byte.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="oaepHash"/> is <see cref="RsaOaepHash.Sha1"/>, which this format does not accept,
    /// or is not a defined value.
    /// </exception>
    /// <remarks>
    /// <see cref="RsaOaepHash.Sha1"/> falls into the rejecting arm on purpose, so that
    /// <see cref="Sha1Byte"/> is unreachable from the write path however a caller reaches it.
    /// </remarks>
    internal static byte ToWireByte(RsaOaepHash oaepHash) => oaepHash switch
    {
        RsaOaepHash.Sha256 => Sha256Byte,
        RsaOaepHash.Sha384 => Sha384Byte,
        RsaOaepHash.Sha512 => Sha512Byte,
        _ => throw new ArgumentOutOfRangeException(
            nameof(oaepHash), oaepHash, Rejection),
    };

    /// <summary>Validates an <see cref="RsaOaepHash"/> supplied by a caller.</summary>
    /// <param name="oaepHash">The value the caller passed.</param>
    /// <param name="paramName">The name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="oaepHash"/> is <see cref="RsaOaepHash.Sha1"/> or is not a defined value.
    /// </exception>
    /// <remarks>
    /// Separate from <see cref="ToWireByte"/> — which rejects the same values — so that a service can
    /// fault synchronously, before it returns a task and before it draws a nonce or touches a key, and so
    /// that the file-path extension can reject the value before it opens either file.
    /// </remarks>
    internal static void ValidateArgument(RsaOaepHash oaepHash, string paramName)
    {
        switch (oaepHash)
        {
            case RsaOaepHash.Sha256:
            case RsaOaepHash.Sha384:
            case RsaOaepHash.Sha512:
                return;

            default:
                throw new ArgumentOutOfRangeException(paramName, oaepHash, Rejection);
        }
    }

    /// <summary>Maps a header byte to its OAEP hash.</summary>
    /// <param name="value">The byte read from header offset 5.</param>
    /// <returns>The corresponding OAEP hash.</returns>
    /// <exception cref="DataEncryptionFormatException">
    /// <paramref name="value"/> is <c>0x00</c>, the reserved <see cref="Sha1Byte"/>, or an undefined
    /// value.
    /// </exception>
    internal static RsaOaepHash FromWireByte(byte value) => value switch
    {
        Sha256Byte => RsaOaepHash.Sha256,
        Sha384Byte => RsaOaepHash.Sha384,
        Sha512Byte => RsaOaepHash.Sha512,
        Sha1Byte => throw new DataEncryptionFormatException(
            $"OAEP-hash byte 0x{value:X2} at header offset 5 is reserved for SHA-1, which this format does not accept."),
        _ => throw new DataEncryptionFormatException(
            $"Undefined OAEP-hash byte 0x{value:X2} at header offset 5."),
    };

    private const string Rejection =
        "The OAEP hash must be SHA-256, SHA-384 or SHA-512; SHA-1 is not accepted by this container format.";
}
