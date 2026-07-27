namespace Enigma.DataEncryption;

/// <summary>
/// The key-establishment method that produced a container — how the 32-byte data key was derived or
/// transported. It is recorded in the container header (offset 2) and determines the layout of the
/// rest of the header.
/// </summary>
/// <remarks>
/// <para>
/// Header byte <c>0x05</c> is <b>reserved</b> for a true RSA + ML-KEM hybrid method and is
/// deliberately absent from this enumeration until that method is implemented. A reader of format
/// version <c>0x10</c> rejects it. See <c>docs/format.md</c> §2.2 and §10.
/// </para>
/// <para>
/// Each service reads only its own method byte, so handing a PBKDF2 container to the RSA service is a
/// format error rather than a silent misparse.
/// </para>
/// </remarks>
public enum EncryptionMethod : byte
{
    /// <summary>
    /// PBKDF2-HMAC-SHA256 key derivation from a password. Header byte <c>0x01</c>; served by
    /// <see cref="IPbkdf2DataEncryptionService"/>.
    /// </summary>
    Pbkdf2 = 0x01,

    /// <summary>
    /// Argon2id key derivation from a password. Header byte <c>0x02</c>; served by
    /// <see cref="IArgon2DataEncryptionService"/>.
    /// </summary>
    Argon2 = 0x02,

    /// <summary>
    /// RSAES-OAEP (SHA-256) key transport under an RSA key pair. Header byte <c>0x03</c>; served by
    /// <see cref="IRsaDataEncryptionService"/>.
    /// </summary>
    Rsa = 0x03,

    /// <summary>
    /// ML-KEM (FIPS 203) key encapsulation. Header byte <c>0x04</c>; served by
    /// <see cref="IMLKemDataEncryptionService"/>.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    MLKem = 0x04,
}
