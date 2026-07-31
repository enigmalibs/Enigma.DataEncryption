using System;
using Enigma.Core.Symmetric.BlockCiphers;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Maps the format's <see cref="Cipher"/> selector onto Enigma.Core's block-cipher services, and
/// validates the selector on both of the paths it can arrive by.
/// </summary>
/// <remarks>
/// An undefined value means two different things depending on where it came from: a header byte the
/// library cannot parse (<see cref="DataEncryptionFormatException"/>) or a caller passing a value that
/// is not a member of the enum (<see cref="ArgumentOutOfRangeException"/>). Both paths exist and are
/// kept distinct — see <c>docs/format.md</c> §9.
/// </remarks>
internal static class CipherResolver
{
    /// <summary>Maps a cipher byte read from header offset 4 to its <see cref="Cipher"/> value.</summary>
    /// <param name="value">The byte read from the header.</param>
    /// <returns>The corresponding cipher.</returns>
    /// <exception cref="DataEncryptionFormatException"><paramref name="value"/> is not a defined cipher byte.</exception>
    internal static Cipher FromHeaderByte(byte value) => value switch
    {
        (byte)Cipher.Aes256Gcm => Cipher.Aes256Gcm,
        (byte)Cipher.Twofish256Gcm => Cipher.Twofish256Gcm,
        (byte)Cipher.Serpent256Gcm => Cipher.Serpent256Gcm,
        (byte)Cipher.Camellia256Gcm => Cipher.Camellia256Gcm,
        _ => throw new DataEncryptionFormatException(
            $"Undefined cipher byte 0x{value:X2} at header offset 4."),
    };

    /// <summary>Validates a <see cref="Cipher"/> supplied by a caller.</summary>
    /// <param name="cipher">The value the caller passed.</param>
    /// <param name="paramName">The name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="cipher"/> is not a defined value.</exception>
    internal static void ValidateArgument(Cipher cipher, string paramName)
    {
        switch (cipher)
        {
            case Cipher.Aes256Gcm:
            case Cipher.Twofish256Gcm:
            case Cipher.Serpent256Gcm:
            case Cipher.Camellia256Gcm:
                return;

            default:
                throw new ArgumentOutOfRangeException(
                    paramName, cipher, "Undefined cipher value.");
        }
    }

    /// <summary>
    /// Creates the block-cipher service for a cipher, through the supplied Enigma.Core factory.
    /// </summary>
    /// <param name="factory">The injected block-cipher service factory.</param>
    /// <param name="cipher">The cipher to resolve — in practice, one read from a container header.</param>
    /// <returns>A configured block-cipher service.</returns>
    /// <exception cref="DataEncryptionFormatException"><paramref name="cipher"/> is not a defined value.</exception>
    internal static IBlockCipherService Resolve(IBlockCipherServiceFactory factory, Cipher cipher) => cipher switch
    {
        Cipher.Aes256Gcm => factory.CreateAesService(),
        Cipher.Twofish256Gcm => factory.CreateTwofishService(),
        Cipher.Serpent256Gcm => factory.CreateSerpentService(),
        Cipher.Camellia256Gcm => factory.CreateCamelliaService(),
        _ => throw new DataEncryptionFormatException(
            $"Undefined cipher byte 0x{(byte)cipher:X2} at header offset 4."),
    };
}
