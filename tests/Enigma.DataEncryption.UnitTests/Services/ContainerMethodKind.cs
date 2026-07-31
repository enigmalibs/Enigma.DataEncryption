namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The five encryption methods, as a theory parameter for the cross-cutting suites that must hold for
/// all of them.
/// </summary>
/// <remarks>
/// Distinct from <see cref="EncryptionMethod"/> on purpose: that enum's values are the container's wire
/// bytes, which several of these suites deliberately corrupt. Naming the <i>service under test</i>
/// separately from the <i>byte in the file</i> keeps "which service" and "which method byte" from being
/// the same variable.
/// </remarks>
public enum ContainerMethodKind
{
    /// <summary>Method <c>0x01</c> — <see cref="IPbkdf2DataEncryptionService"/>.</summary>
    Pbkdf2,

    /// <summary>Method <c>0x02</c> — <see cref="IArgon2DataEncryptionService"/>.</summary>
    Argon2,

    /// <summary>Method <c>0x03</c> — <see cref="IRsaDataEncryptionService"/>.</summary>
    Rsa,

    /// <summary>Method <c>0x04</c> — <see cref="IMLKemDataEncryptionService"/>.</summary>
    // ReSharper disable once InconsistentNaming
    MLKem,

    /// <summary>Method <c>0x05</c> — <see cref="IHybridDataEncryptionService"/>. The only two-credential method.</summary>
    Hybrid,
}
