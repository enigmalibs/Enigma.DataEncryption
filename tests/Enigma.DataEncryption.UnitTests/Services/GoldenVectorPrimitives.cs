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
