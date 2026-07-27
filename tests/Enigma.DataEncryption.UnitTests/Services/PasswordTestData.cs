using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The fixed inputs the password suites share, and the two-line helpers that turn a container into
/// bytes and back.
/// </summary>
/// <remarks>
/// The salt and nonce come from <see cref="FormatTestData"/> so that a container produced here lines up
/// with the header vectors PHASE01 already pinned.
/// </remarks>
internal static class PasswordTestData
{
    /// <summary>The password every suite encrypts under.</summary>
    internal const string Password = "correct horse battery staple";

    /// <summary>A password that differs from <see cref="Password"/> in exactly one bit.</summary>
    internal const string WrongPassword = "correct horse battery stapld";

    /// <summary>The UTF-8 bytes of <see cref="Password"/>, as a fresh array.</summary>
    /// <returns>The password bytes.</returns>
    internal static byte[] PasswordBytes() => Encoding.UTF8.GetBytes(Password);

    /// <summary>The characters of <see cref="Password"/>, as a fresh array.</summary>
    /// <returns>The password characters.</returns>
    internal static char[] PasswordChars() => Password.ToCharArray();

    /// <summary>The UTF-8 bytes of <see cref="WrongPassword"/>, as a fresh array.</summary>
    /// <returns>The wrong password's bytes.</returns>
    internal static byte[] WrongPasswordBytes() => Encoding.UTF8.GetBytes(WrongPassword);

    /// <summary>A deterministic plaintext of the requested length.</summary>
    /// <param name="length">How many bytes.</param>
    /// <returns>The plaintext bytes.</returns>
    internal static byte[] Plaintext(int length = 512)
    {
        byte[] plaintext = new byte[length];
        for (int i = 0; i < length; i++)
        {
            plaintext[i] = PatternStream.ByteAt(i);
        }

        return plaintext;
    }

    /// <summary>An adapter whose salt and nonce are the fixed ones, so its output is reproducible.</summary>
    /// <param name="method">Which method to drive.</param>
    /// <returns>The adapter.</returns>
    internal static PasswordServiceAdapter Deterministic(PasswordMethod method) =>
        PasswordServiceAdapter.Create(method, new FixedRandomSource(FormatTestData.Salt(), FormatTestData.Nonce()));

    /// <summary>Encrypts a plaintext and returns the complete container.</summary>
    /// <param name="adapter">The method to encrypt with.</param>
    /// <param name="plaintext">The bytes to protect.</param>
    /// <param name="cipher">The payload cipher.</param>
    /// <param name="password">The password; <see langword="null"/> uses <see cref="Password"/>.</param>
    /// <returns>The container bytes.</returns>
    internal static async Task<byte[]> EncryptToBytesAsync(
        PasswordServiceAdapter adapter,
        byte[] plaintext,
        Cipher cipher = Cipher.Aes256Gcm,
        byte[]? password = null)
    {
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await adapter.EncryptAsync(input, output, cipher, password ?? PasswordBytes(), null, CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>Decrypts a container and returns the recovered plaintext.</summary>
    /// <param name="adapter">The method to decrypt with.</param>
    /// <param name="container">The container bytes.</param>
    /// <param name="password">The password; <see langword="null"/> uses <see cref="Password"/>.</param>
    /// <param name="limits">The bounds to apply; <see langword="null"/> uses the defaults.</param>
    /// <returns>The recovered plaintext.</returns>
    internal static async Task<byte[]> DecryptToBytesAsync(
        PasswordServiceAdapter adapter,
        byte[] container,
        byte[]? password = null,
        DataEncryptionLimits? limits = null)
    {
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();
        await adapter.DecryptAsync(input, output, password ?? PasswordBytes(), limits, null, CancellationToken.None);
        return output.ToArray();
    }

    /// <summary>Reads a committed fixture file from beside the test assembly.</summary>
    /// <param name="fileName">The file's name within <c>Services/Fixtures</c>.</param>
    /// <returns>The file's bytes.</returns>
    internal static byte[] Fixture(string fileName) =>
        File.ReadAllBytes(Path.Combine("Services", "Fixtures", fileName));
}
