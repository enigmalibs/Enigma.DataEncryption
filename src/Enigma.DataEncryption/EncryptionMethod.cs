namespace Enigma.DataEncryption;

/// <summary>
/// The key-establishment method that produced a container — how the 32-byte data key was derived or
/// transported. It is recorded in the container header (offset 2) and determines the layout of the
/// rest of the header.
/// </summary>
/// <remarks>
/// <para>
/// Header bytes <c>0x06</c>–<c>0xFF</c> are unassigned; a reader of format version <c>0x10</c> rejects
/// them. Byte <c>0x05</c> was reserved by earlier revisions of the format and is now
/// <see cref="Hybrid"/> — which is the reservation working as intended, since the hybrid method landed
/// without a format-version bump. See <c>docs/format.md</c> §2.2 and §10.
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

    /// <summary>
    /// True hybrid: RSAES-OAEP (SHA-256) key transport <b>and</b> ML-KEM (FIPS 203) key encapsulation,
    /// with the data key combined from both secrets so that breaking one primitive is not enough. Header
    /// byte <c>0x05</c>; served by <see cref="IHybridDataEncryptionService"/>.
    /// </summary>
    /// <remarks>
    /// The only method requiring two credentials in both directions. See <c>docs/format.md</c> §3.5, and
    /// §3.5.1 for the key combiner.
    /// </remarks>
    Hybrid = 0x05,
}
