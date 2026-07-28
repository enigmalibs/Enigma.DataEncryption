using System;
using System.Text;
using Enigma.Core.Hashing.Hmac;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The hybrid method's key combiner: turns an RSA-transported secret and an ML-KEM shared secret into
/// the one 32-byte data key, in a way that stays secure as long as <b>either</b> of them does.
/// </summary>
/// <remarks>
/// <para>Per <c>docs/format.md</c> §3.5.1:</para>
/// <code>
/// T    = LE32(N) ‖ wrappedRsaSecret ‖ LE32(M) ‖ encapsulation
///
/// Krsa = HMAC-SHA256(key: rsaSecret, message: ASCII("Enigma.DataEncryption/hybrid/rsa/v1")   ‖ T)
/// Kkem = HMAC-SHA256(key: kemSecret, message: ASCII("Enigma.DataEncryption/hybrid/mlkem/v1") ‖ T)
///
/// K    = Krsa XOR Kkem
/// </code>
/// <para>
/// <b>This is a split-key PRF, not an XOR of the secrets.</b> Each secret is the HMAC <i>key</i> of its
/// own invocation and never appears in a message, so if either one is a uniformly random value the
/// adversary does not hold, that branch's output is indistinguishable from random and XOR-ing the other
/// branch into it — even a fully known other branch — leaves it indistinguishable from random. That
/// one-line argument in each direction <i>is</i> the security property the whole method exists for, and
/// it needs nothing beyond "HMAC-SHA256 is a PRF", which is what <see cref="KeyConfirmation"/> already
/// assumes. XOR-ing the two secrets together, or concatenating them into one key, would not give it.
/// </para>
/// <para>
/// <b>Mind the argument order.</b> <see cref="IHmacService.ComputeHmac"/> takes <c>(data, key)</c> —
/// message first, key second — the opposite of the order the formulae above are written in. Swapping
/// them yields a construction that round-trips perfectly and matches no specification, so only a
/// hard-coded vector catches it; <c>HybridKeyCombinerTests</c> is that vector.
/// </para>
/// <para>
/// <b>The two labels must differ.</b> They are what stops the degenerate <c>rsaSecret == kemSecret</c>,
/// where a shared label would give <c>Krsa == Kkem</c> and therefore an all-zero data key — readable by
/// anyone holding neither private key. That case is not a 2⁻²⁵⁶ accident: a hostile sender encapsulates
/// first, sees <c>kemSecret</c>, and then chooses what to wrap under RSA (§3.5.2).
/// </para>
/// </remarks>
internal static class HybridKeyCombiner
{
    /// <summary>
    /// The 35-byte US-ASCII label domain-separating the RSA branch, with no trailing NUL. In hex:
    /// <c>45 6E 69 67 6D 61 2E 44 61 74 61 45 6E 63 72 79 70 74 69 6F 6E 2F 68 79 62 72 69 64 2F 72 73
    /// 61 2F 76 31</c>.
    /// </summary>
    private const string RsaLabel = "Enigma.DataEncryption/hybrid/rsa/v1";

    /// <summary>
    /// The 37-byte US-ASCII label domain-separating the ML-KEM branch, with no trailing NUL. In hex:
    /// <c>45 6E 69 67 6D 61 2E 44 61 74 61 45 6E 63 72 79 70 74 69 6F 6E 2F 68 79 62 72 69 64 2F 6D 6C
    /// 6B 65 6D 2F 76 31</c>.
    /// </summary>
    private const string MLKemLabel = "Enigma.DataEncryption/hybrid/mlkem/v1";

    /// <summary>
    /// Combines the two transported secrets, bound to the two ciphertexts that carried them, into the
    /// 32-byte data key.
    /// </summary>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="rsaSecret">The 32-byte secret recovered from — or about to be wrapped into — the RSA field.</param>
    /// <param name="kemSecret">The 32-byte FIPS 203 shared secret.</param>
    /// <param name="wrappedRsaSecret">The RSAES-OAEP ciphertext carrying <paramref name="rsaSecret"/>.</param>
    /// <param name="encapsulation">The ML-KEM encapsulation carrying <paramref name="kemSecret"/>.</param>
    /// <returns>The 32-byte data key <c>K</c>.</returns>
    /// <remarks>
    /// Both branches are computed unconditionally and the intermediates are cleared in a
    /// <c>finally</c> — they are as much key material as the result is.
    /// </remarks>
    internal static byte[] Combine(
        IHmacService hmacSha256,
        byte[] rsaSecret,
        byte[] kemSecret,
        byte[] wrappedRsaSecret,
        byte[] encapsulation)
    {
        byte[] transcript = BuildTranscript(wrappedRsaSecret, encapsulation);

        byte[]? rsaBranch = null;
        byte[]? kemBranch = null;
        try
        {
            rsaBranch = Branch(hmacSha256, RsaLabel, transcript, rsaSecret);
            kemBranch = Branch(hmacSha256, MLKemLabel, transcript, kemSecret);

            byte[] dataKey = new byte[DataEncryptionDefaults.DataKeySizeBytes];
            for (int i = 0; i < dataKey.Length; i++)
            {
                dataKey[i] = (byte)(rsaBranch[i] ^ kemBranch[i]);
            }

            return dataKey;
        }
        finally
        {
            CryptoHelpers.Clear(rsaBranch, kemBranch);
        }
    }

    /// <summary>
    /// Builds the combiner transcript <c>T</c> — the length-prefixed pair of ciphertexts.
    /// </summary>
    /// <param name="wrappedRsaSecret">The RSAES-OAEP ciphertext.</param>
    /// <param name="encapsulation">The ML-KEM encapsulation.</param>
    /// <returns>
    /// <c>LE32(N) ‖ wrappedRsaSecret ‖ LE32(M) ‖ encapsulation</c> — byte-for-byte the hybrid header's
    /// slice from offset 18 up to the key-confirmation tag.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The lengths are included, rather than the two ciphertexts simply concatenated, so that the
    /// encoding is unambiguous: both fields are variable-length, and without the lengths a shorter
    /// wrapped secret followed by a longer encapsulation could produce the same byte sequence as the
    /// other way round.
    /// </para>
    /// <para>
    /// That it coincides exactly with a header slice is deliberate — <c>HybridKeyCombinerTests</c> holds
    /// the two side by side — so the transcript can be located in a hex dump rather than trusted.
    /// </para>
    /// </remarks>
    internal static byte[] BuildTranscript(byte[] wrappedRsaSecret, byte[] encapsulation)
    {
        byte[] transcript = new byte[
            FormatLayout.Int32Length + wrappedRsaSecret.Length
            + FormatLayout.Int32Length + encapsulation.Length];

        int offset = 0;
        WriteInt32LittleEndian(transcript, ref offset, wrappedRsaSecret.Length);
        Buffer.BlockCopy(wrappedRsaSecret, 0, transcript, offset, wrappedRsaSecret.Length);
        offset += wrappedRsaSecret.Length;
        WriteInt32LittleEndian(transcript, ref offset, encapsulation.Length);
        Buffer.BlockCopy(encapsulation, 0, transcript, offset, encapsulation.Length);

        return transcript;
    }

    /// <summary>Computes one branch of the combiner: <c>HMAC-SHA256(key: secret, message: label ‖ T)</c>.</summary>
    /// <param name="hmacSha256">An HMAC-SHA256 service.</param>
    /// <param name="label">The branch's domain-separation label.</param>
    /// <param name="transcript">The transcript <c>T</c>.</param>
    /// <param name="secret">The 32-byte secret, used as the HMAC key.</param>
    /// <returns>The 32-byte HMAC output.</returns>
    private static byte[] Branch(IHmacService hmacSha256, string label, byte[] transcript, byte[] secret)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        byte[] message = new byte[labelBytes.Length + transcript.Length];
        Buffer.BlockCopy(labelBytes, 0, message, 0, labelBytes.Length);
        Buffer.BlockCopy(transcript, 0, message, labelBytes.Length, transcript.Length);

        return hmacSha256.ComputeHmac(message, secret);
    }

    private static void WriteInt32LittleEndian(byte[] destination, ref int offset, int value)
    {
        destination[offset++] = (byte)value;
        destination[offset++] = (byte)(value >> 8);
        destination[offset++] = (byte)(value >> 16);
        destination[offset++] = (byte)(value >> 24);
    }
}
