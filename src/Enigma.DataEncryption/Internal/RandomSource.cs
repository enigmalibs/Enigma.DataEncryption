using Enigma.Core.Utils;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The production <see cref="IRandomSource"/>, delegating to Enigma.Core's
/// <see cref="RandomUtils"/> (a thread-static <c>SecureRandom</c>).
/// </summary>
internal sealed class RandomSource : IRandomSource
{
    /// <inheritdoc />
    public byte[] GenerateRandomBytes(int size) => RandomUtils.GenerateRandomBytes(size);
}
