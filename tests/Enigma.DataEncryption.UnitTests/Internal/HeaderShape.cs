namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// The five header layouts of <c>docs/format.md</c> §3, used to drive the header suites as theories.
/// </summary>
/// <remarks>
/// Public because xUnit theory parameters must be at least as visible as the test methods that take
/// them.
/// </remarks>
public enum HeaderShape
{
    /// <summary>Method <c>0x01</c> — PBKDF2, 53 bytes.</summary>
    Pbkdf2,

    /// <summary>Method <c>0x02</c> — Argon2, 61 bytes.</summary>
    Argon2,

    /// <summary>Method <c>0x03</c> — RSA, 37 + N bytes.</summary>
    Rsa,

    /// <summary>Method <c>0x04</c> — ML-KEM, 38 + N bytes.</summary>
    // ReSharper disable once InconsistentNaming
    MLKem,

    /// <summary>Method <c>0x05</c> — hybrid RSA + ML-KEM, 42 + N + M bytes.</summary>
    Hybrid,
}
