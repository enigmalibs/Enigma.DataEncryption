namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The library's source of cryptographic randomness — salts, GCM nonces and, for the key-transport
/// methods, the data key itself.
/// </summary>
/// <remarks>
/// This seam exists so the golden-vector tests can pin the encrypt path byte-for-byte by supplying
/// deterministic bytes. It is deliberately <c>internal</c>: a public hook for injecting randomness
/// into a cryptography library is a footgun. The test assembly reaches it through
/// <c>InternalsVisibleTo</c>.
/// </remarks>
internal interface IRandomSource
{
    /// <summary>Generates the requested number of cryptographically secure random bytes.</summary>
    /// <param name="size">The number of bytes to generate. Must be greater than zero.</param>
    /// <returns>A new array of <paramref name="size"/> random bytes.</returns>
    byte[] GenerateRandomBytes(int size);
}
