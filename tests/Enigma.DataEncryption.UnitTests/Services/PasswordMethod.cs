namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The two password-based container methods, used to drive the shared suites as theories so that every
/// cross-cutting property is asserted for both.
/// </summary>
/// <remarks>
/// Public because xUnit theory parameters must be at least as visible as the test methods that take
/// them.
/// </remarks>
public enum PasswordMethod
{
    /// <summary>Method <c>0x01</c> — PBKDF2-HMAC-SHA256, 53-byte header.</summary>
    Pbkdf2,

    /// <summary>Method <c>0x02</c> — Argon2id, 61-byte header.</summary>
    Argon2,
}
