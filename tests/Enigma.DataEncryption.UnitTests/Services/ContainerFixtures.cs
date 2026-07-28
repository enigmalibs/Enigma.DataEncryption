using System.IO;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The two things every service suite needs from disk and from thin air: a committed fixture file, and a
/// deterministic plaintext.
/// </summary>
/// <remarks>
/// Fixture files live in <c>Services/Fixtures</c> and are copied next to the test assembly by the
/// csproj's copy-glob, so they are read by relative path. The plaintext is generated from
/// <see cref="PatternStream"/>'s pattern, which keeps the small in-memory payloads and the large streamed
/// ones byte-compatible.
/// </remarks>
internal static class ContainerFixtures
{
    /// <summary>Reads a committed fixture file from beside the test assembly.</summary>
    /// <param name="fileName">The file's name within <c>Services/Fixtures</c>.</param>
    /// <returns>The file's bytes.</returns>
    internal static byte[] Read(string fileName) =>
        File.ReadAllBytes(Path.Combine("Services", "Fixtures", fileName));

    /// <summary>Reads a committed fixture file as text.</summary>
    /// <param name="fileName">The file's name within <c>Services/Fixtures</c>.</param>
    /// <returns>The file's contents.</returns>
    internal static string ReadText(string fileName) =>
        File.ReadAllText(Path.Combine("Services", "Fixtures", fileName));

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
}
