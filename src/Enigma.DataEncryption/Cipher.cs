namespace Enigma.DataEncryption;

/// <summary>
/// The 256-bit AEAD block cipher used to encrypt a container's payload. Every value runs in GCM mode
/// with a 128-bit authentication tag; the choice is recorded in the container header (offset 4) so a
/// reader needs no out-of-band knowledge.
/// </summary>
/// <remarks>
/// All four ciphers are equivalent 256-bit AEADs, so no value is a downgrade of another — this is the
/// only algorithmic degree of freedom the format offers. Everything else (key size, nonce size, tag
/// size, key-derivation function and its variant) is a fixed invariant of the format and is not
/// header-selectable. See <c>docs/format.md</c> §2.4 and §4.
/// </remarks>
public enum Cipher : byte
{
    /// <summary>AES-256 in GCM mode. Header byte <c>0x01</c>.</summary>
    Aes256Gcm = 0x01,

    /// <summary>Twofish-256 in GCM mode. Header byte <c>0x02</c>.</summary>
    Twofish256Gcm = 0x02,

    /// <summary>Serpent-256 in GCM mode. Header byte <c>0x03</c>.</summary>
    Serpent256Gcm = 0x03,

    /// <summary>Camellia-256 in GCM mode. Header byte <c>0x04</c>.</summary>
    Camellia256Gcm = 0x04,
}
