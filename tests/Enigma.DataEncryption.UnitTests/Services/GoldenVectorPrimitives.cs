using System;
using System.Security.Cryptography;
using System.Text;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The .NET platform's own cryptographic primitives, used to rebuild a golden container from
/// <c>docs/format.md</c> without going through this library or Enigma.Core at all.
/// </summary>
/// <remarks>
/// <para>
/// A golden vector that was produced by the code it tests only proves the code has not changed. These
/// helpers make the vectors independent instead: <see cref="Rfc2898DeriveBytes"/>,
/// <see cref="HMACSHA256"/> and <see cref="AesGcm"/> are the platform's implementations, sharing no code
/// with the BouncyCastle-backed path under test. Where the two agree, the format is right and not merely
/// self-consistent.
/// </para>
/// <para>
/// Argon2id and the three non-AES ciphers have no platform implementation, so those parts of the vectors
/// are pinned by values computed with external tools — recorded, with the command that produced them, at
/// the site that uses them.
/// </para>
/// </remarks>
internal static class GoldenVectorPrimitives
{
    /// <summary>The 27-byte key-confirmation label of <c>docs/format.md</c> §6.</summary>
    private static readonly byte[] Label = Encoding.ASCII.GetBytes("Enigma.DataEncryption/kc/v1");

    /// <summary>The 35-byte RSA-branch label of the hybrid key combiner, <c>docs/format.md</c> §3.5.1.</summary>
    private static readonly byte[] HybridRsaLabel =
        Encoding.ASCII.GetBytes("Enigma.DataEncryption/hybrid/rsa/v1");

    /// <summary>The 37-byte ML-KEM-branch label of the hybrid key combiner, <c>docs/format.md</c> §3.5.1.</summary>
    private static readonly byte[] HybridMLKemLabel =
        Encoding.ASCII.GetBytes("Enigma.DataEncryption/hybrid/mlkem/v1");

    /// <summary>Derives a PBKDF2-HMAC-SHA256 data key with the platform's implementation.</summary>
    /// <param name="password">The password bytes.</param>
    /// <param name="salt">The 16-byte salt.</param>
    /// <param name="iterations">The iteration count.</param>
    /// <returns>The 32-byte data key.</returns>
    internal static byte[] Pbkdf2Key(byte[] password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(
            password, salt, iterations, HashAlgorithmName.SHA256, DataEncryptionDefaults.DataKeySizeBytes);

    /// <summary>
    /// Computes the 16-byte key-confirmation tag straight from the formulae of §6, with the platform's
    /// HMAC.
    /// </summary>
    /// <param name="dataKey">The 32-byte data key <c>K</c>.</param>
    /// <param name="headerBytesBeforeTag">Every header byte preceding the tag.</param>
    /// <returns>The leftmost 16 bytes of the second HMAC.</returns>
    internal static byte[] KeyConfirmationTag(byte[] dataKey, byte[] headerBytesBeforeTag)
    {
        using HMACSHA256 derivation = new(dataKey);
        byte[] confirmationKey = derivation.ComputeHash(Label);

        using HMACSHA256 mac = new(confirmationKey);
        return mac.ComputeHash(headerBytesBeforeTag)[..DataEncryptionDefaults.KeyConfirmationTagSizeBytes];
    }

    /// <summary>
    /// Runs the hybrid key combiner of <c>docs/format.md</c> §3.5.1 with the platform's HMAC, straight
    /// from the formulae.
    /// </summary>
    /// <param name="rsaSecret">The 32-byte secret the RSAES-OAEP ciphertext carries.</param>
    /// <param name="kemSecret">The 32-byte FIPS 203 shared secret.</param>
    /// <param name="wrappedRsaSecret">The RSAES-OAEP ciphertext.</param>
    /// <param name="encapsulation">The ML-KEM encapsulation.</param>
    /// <returns>The 32-byte combined data key.</returns>
    /// <remarks>
    /// <para>
    /// Shares no code with <c>HybridKeyCombiner</c> — that is the entire point. The library's combiner is
    /// built on Enigma.Core's BouncyCastle-backed HMAC; this one is <see cref="HMACSHA256"/>. Where the
    /// two agree, the combiner matches the specification rather than merely matching itself.
    /// </para>
    /// <para>
    /// Note that each secret is the <b>key</b> of its own HMAC and the label-plus-transcript is the
    /// <b>message</b>. Swapping the two would still round-trip; only a comparison against this
    /// independent implementation, and against the hard-coded vector in <c>HybridKeyCombinerTests</c>,
    /// catches it.
    /// </para>
    /// </remarks>
    internal static byte[] HybridDataKey(
        byte[] rsaSecret,
        byte[] kemSecret,
        byte[] wrappedRsaSecret,
        byte[] encapsulation)
    {
        byte[] transcript = HybridTranscript(wrappedRsaSecret, encapsulation);

        using HMACSHA256 rsaBranch = new(rsaSecret);
        using HMACSHA256 kemBranch = new(kemSecret);

        byte[] left = rsaBranch.ComputeHash([.. HybridRsaLabel, .. transcript]);
        byte[] right = kemBranch.ComputeHash([.. HybridMLKemLabel, .. transcript]);

        byte[] dataKey = new byte[DataEncryptionDefaults.DataKeySizeBytes];
        for (int i = 0; i < dataKey.Length; i++)
        {
            dataKey[i] = (byte)(left[i] ^ right[i]);
        }

        return dataKey;
    }

    /// <summary>
    /// The combiner transcript <c>T</c> of §3.5.1: the two ciphertexts, each preceded by its
    /// little-endian length.
    /// </summary>
    /// <param name="wrappedRsaSecret">The RSAES-OAEP ciphertext.</param>
    /// <param name="encapsulation">The ML-KEM encapsulation.</param>
    /// <returns><c>LE32(N) ‖ wrappedRsaSecret ‖ LE32(M) ‖ encapsulation</c>.</returns>
    internal static byte[] HybridTranscript(byte[] wrappedRsaSecret, byte[] encapsulation) =>
    [
        .. LittleEndian(wrappedRsaSecret.Length),
        .. wrappedRsaSecret,
        .. LittleEndian(encapsulation.Length),
        .. encapsulation,
    ];

    /// <summary>The little-endian encoding of a 32-bit value, as <c>docs/format.md</c> §1.1 writes it.</summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The four bytes.</returns>
    private static byte[] LittleEndian(int value) =>
        [(byte)value, (byte)(value >> 8), (byte)(value >> 16), (byte)(value >> 24)];

    /// <summary>
    /// Produces an AES-256-GCM payload — ciphertext followed by the 128-bit tag — with the platform's
    /// implementation.
    /// </summary>
    /// <param name="dataKey">The 32-byte data key.</param>
    /// <param name="nonce">The 12-byte nonce.</param>
    /// <param name="associatedData">The complete header.</param>
    /// <param name="plaintext">The payload plaintext.</param>
    /// <returns>The ciphertext concatenated with the authentication tag.</returns>
    internal static byte[] AesGcmPayload(
        byte[] dataKey,
        byte[] nonce,
        byte[] associatedData,
        byte[] plaintext)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[DataEncryptionDefaults.GcmMacSizeBits / 8];

        using AesGcm aes = new(dataKey, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        byte[] payload = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, payload, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, payload, ciphertext.Length, tag.Length);
        return payload;
    }
}
