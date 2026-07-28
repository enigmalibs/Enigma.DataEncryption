using System;
using System.Text;
using Enigma.Core.Hashing.Hmac;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The header's key-confirmation tag — the uniform, fast wrong-credential signal every method shares.
/// </summary>
/// <remarks>
/// <para>Per <c>docs/format.md</c> §6:</para>
/// <code>
/// kcKey = HMAC-SHA256(key: K,     message: ASCII("Enigma.DataEncryption/kc/v1"))
/// kcTag = HMAC-SHA256(key: kcKey, message: headerBytesBeforeTag)[0..16]
/// </code>
/// <para>
/// <b>Mind the argument order.</b> <see cref="IHmacService.ComputeHmac"/> takes
/// <c>(data, key)</c> — message first, key second — which is the opposite of the order the formulae
/// above are written in. Swapping them yields a construction that round-trips perfectly and matches no
/// specification, so only a hard-coded vector would catch it; <c>KeyConfirmationTests</c> is that
/// vector.
/// </para>
/// <para>
/// <c>kcKey</c> is derived rather than MAC-ing under <c>K</c> directly so that no tag computed under
/// the data key itself is ever published (§6.1).
/// </para>
/// </remarks>
internal static class KeyConfirmation
{
    /// <summary>
    /// The 27-byte US-ASCII derivation label, with no trailing NUL. In hex:
    /// <c>45 6E 69 67 6D 61 2E 44 61 74 61 45 6E 63 72 79 70 74 69 6F 6E 2F 6B 63 2F 76 31</c>.
    /// </summary>
    private const string Label = "Enigma.DataEncryption/kc/v1";

    /// <summary>Computes the 16-byte key-confirmation tag for a header.</summary>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="dataKey">The 32-byte data key <c>K</c>.</param>
    /// <param name="headerBytesBeforeTag">Every header byte preceding the tag.</param>
    /// <returns>The leftmost 16 bytes of the HMAC.</returns>
    internal static byte[] ComputeTag(IHmacService hmacSha256, byte[] dataKey, byte[] headerBytesBeforeTag)
    {
        byte[]? confirmationKey = null;
        byte[]? mac = null;
        try
        {
            confirmationKey = hmacSha256.ComputeHmac(Encoding.ASCII.GetBytes(Label), dataKey);
            mac = hmacSha256.ComputeHmac(headerBytesBeforeTag, confirmationKey);

            byte[] tag = new byte[DataEncryptionDefaults.KeyConfirmationTagSizeBytes];
            Array.Copy(mac, 0, tag, 0, tag.Length);
            return tag;
        }
        finally
        {
            CryptoHelpers.Clear(confirmationKey, mac);
        }
    }

    /// <summary>
    /// Recomputes the tag for a header and compares it, in constant time, against the one the header
    /// carries.
    /// </summary>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="dataKey">The 32-byte data key <c>K</c>, as just derived, unwrapped or decapsulated.</param>
    /// <param name="headerBytesBeforeTag">Every header byte preceding the tag.</param>
    /// <param name="expectedTag">The tag read from the header.</param>
    /// <returns><see langword="true"/> when the tags match.</returns>
    internal static bool Verify(
        IHmacService hmacSha256,
        byte[] dataKey,
        byte[] headerBytesBeforeTag,
        byte[] expectedTag)
    {
        byte[]? actualTag = null;
        try
        {
            actualTag = ComputeTag(hmacSha256, dataKey, headerBytesBeforeTag);
            return CryptoHelpers.FixedTimeEquals(actualTag, expectedTag);
        }
        finally
        {
            CryptoHelpers.Clear(actualTag);
        }
    }
}
