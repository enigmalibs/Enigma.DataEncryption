namespace Enigma.DataEncryption;

/// <summary>
/// The format's fixed sizes and its default key-derivation cost parameters.
/// </summary>
/// <remarks>
/// <para>
/// The size constants (<see cref="DataKeySizeBytes"/>, <see cref="NonceSizeBytes"/>,
/// <see cref="SaltSizeBytes"/>, <see cref="GcmMacSizeBits"/>,
/// <see cref="KeyConfirmationTagSizeBytes"/>) and <see cref="FormatVersion"/> are <b>invariants of
/// the format</b>: they are not stored in the container header and are not selectable. Changing one
/// would be a new format version.
/// </para>
/// <para>
/// The cost constants (<see cref="Pbkdf2Iterations"/>, <see cref="Argon2Iterations"/>,
/// <see cref="Argon2MemorySizeKb"/>, <see cref="Argon2DegreeOfParallelism"/>) are only
/// <b>defaults</b>: they are chosen at encryption time, written into the header, and read back by the
/// reader. Callers may override them per call; the upper bounds accepted when reading are set by
/// <see cref="DataEncryptionLimits"/>.
/// </para>
/// <para>See <c>docs/format.md</c> §4.</para>
/// </remarks>
public static class DataEncryptionDefaults
{
    /// <summary>
    /// The format version written to, and required at, header offset 3. Values <c>0x01</c>–<c>0x0F</c>
    /// are reserved for legacy <c>Enigma.Cryptography.DataEncryption</c> containers and are rejected.
    /// </summary>
    public const byte FormatVersion = 0x10;

    /// <summary>
    /// The default PBKDF2 iteration count: 600,000 — the OWASP 2023 floor for PBKDF2-HMAC-SHA256.
    /// </summary>
    public const int Pbkdf2Iterations = 600_000;

    /// <summary>
    /// The default Argon2 iteration count (passes over memory): 3 — RFC 9106's second recommended
    /// option, together with <see cref="Argon2MemorySizeKb"/> and
    /// <see cref="Argon2DegreeOfParallelism"/>.
    /// </summary>
    public const int Argon2Iterations = 3;

    /// <summary>
    /// The default Argon2 memory cost in kibibytes: 65,536 KiB (64 MiB) — RFC 9106's second
    /// recommended option.
    /// </summary>
    public const int Argon2MemorySizeKb = 65_536;

    /// <summary>
    /// The default Argon2 degree of parallelism (lanes): 4 — RFC 9106's second recommended option.
    /// </summary>
    public const int Argon2DegreeOfParallelism = 4;

    /// <summary>
    /// The data-key size in bytes: 32 (256-bit). Fixed by the format for every method.
    /// </summary>
    public const int DataKeySizeBytes = 32;

    /// <summary>
    /// The GCM nonce size in bytes: 12 (96-bit). Fixed by the format for every method.
    /// </summary>
    public const int NonceSizeBytes = 12;

    /// <summary>
    /// The PBKDF2 / Argon2 salt size in bytes: 16. Fixed by the format.
    /// </summary>
    public const int SaltSizeBytes = 16;

    /// <summary>
    /// The GCM authentication tag size in bits: 128. Fixed by the format; equal to
    /// <c>Enigma.Core.Symmetric.BlockCiphers.GcmMacSize.MaxBits</c>.
    /// </summary>
    public const int GcmMacSizeBits = 128;

    /// <summary>
    /// The key-confirmation tag size in bytes: 16 — the leftmost half of an HMAC-SHA256 output. Fixed
    /// by the format; it is the last field of every header.
    /// </summary>
    public const int KeyConfirmationTagSizeBytes = 16;
}
