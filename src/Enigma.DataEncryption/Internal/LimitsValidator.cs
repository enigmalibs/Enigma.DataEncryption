namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Validates the cost and length fields read from a container header against
/// <see cref="DataEncryptionLimits"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every check here runs <b>before any allocation or key-derivation work</b>, which is the entire
/// point of the limits: a header claiming two billion Argon2 iterations, or a gigabyte of Argon2
/// memory, must be rejected by arithmetic rather than survived by computation. Reading a bounded
/// integer and comparing it is cheap; acting on it first is not.
/// </para>
/// <para>
/// A field that is <c>&lt;= 0</c> is as much a format error as one over its cap — zero iterations is
/// not a cheap derivation, it is a malformed header. See <c>docs/format.md</c> §8.
/// </para>
/// </remarks>
internal static class LimitsValidator
{
    /// <summary>Validates the PBKDF2 iteration count from a method-<c>0x01</c> header.</summary>
    /// <param name="iterations">The value read from header offset 33.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <exception cref="DataEncryptionFormatException">The value is <c>&lt;= 0</c> or above its cap.</exception>
    internal static void ValidatePbkdf2Iterations(int iterations, DataEncryptionLimits limits) =>
        Validate(iterations, limits.MaxPbkdf2Iterations, "PBKDF2 iteration count");

    /// <summary>Validates the three cost fields of a method-<c>0x02</c> header.</summary>
    /// <param name="iterations">The value read from header offset 33.</param>
    /// <param name="degreeOfParallelism">The value read from header offset 37.</param>
    /// <param name="memorySizeKb">The value read from header offset 41.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <exception cref="DataEncryptionFormatException">Any value is <c>&lt;= 0</c> or above its cap.</exception>
    internal static void ValidateArgon2(
        int iterations,
        int degreeOfParallelism,
        int memorySizeKb,
        DataEncryptionLimits limits)
    {
        Validate(iterations, limits.MaxArgon2Iterations, "Argon2 iteration count");
        Validate(degreeOfParallelism, limits.MaxArgon2DegreeOfParallelism, "Argon2 degree of parallelism");
        Validate(memorySizeKb, limits.MaxArgon2MemorySizeKb, "Argon2 memory size in KiB");
    }

    /// <summary>Validates the wrapped-key length of a method-<c>0x03</c> header.</summary>
    /// <param name="wrappedKeyLength">The value read from header offset 17.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <exception cref="DataEncryptionFormatException">The value is <c>&lt;= 0</c> or above its cap.</exception>
    internal static void ValidateWrappedKeyLength(int wrappedKeyLength, DataEncryptionLimits limits) =>
        Validate(wrappedKeyLength, limits.MaxWrappedKeyLength, "RSA wrapped-key length");

    /// <summary>Validates the encapsulation length of a method-<c>0x04</c> header.</summary>
    /// <param name="encapsulationLength">The value read from header offset 18.</param>
    /// <param name="limits">The bounds to apply.</param>
    /// <exception cref="DataEncryptionFormatException">The value is <c>&lt;= 0</c> or above its cap.</exception>
    internal static void ValidateEncapsulationLength(int encapsulationLength, DataEncryptionLimits limits) =>
        Validate(encapsulationLength, limits.MaxEncapsulationLength, "ML-KEM encapsulation length");

    private static void Validate(int value, int maximum, string field)
    {
        if (value <= 0)
        {
            throw new DataEncryptionFormatException(
                $"Header field '{field}' is {value}; it must be greater than zero (maximum {maximum}).");
        }

        if (value > maximum)
        {
            throw new DataEncryptionFormatException(
                $"Header field '{field}' is {value}, which exceeds the maximum of {maximum}.");
        }
    }
}
