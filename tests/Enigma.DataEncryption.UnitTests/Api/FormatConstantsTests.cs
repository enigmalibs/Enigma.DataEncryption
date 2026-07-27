using Enigma.DataEncryption;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Api;

/// <summary>
/// Pins the wire constants of the container format against <c>docs/format.md</c>. Every literal here
/// is transcribed from that document, so a change to either side that is not mirrored in the other
/// fails the build. The spec is the contract; this test is what keeps the code honest about it.
/// </summary>
/// <remarks>
/// These assertions are deliberately literal rather than derived — reading a constant back through
/// the constant that defines it would assert nothing.
/// </remarks>
public sealed class FormatConstantsTests
{
    // --- §2.2 Method bytes -------------------------------------------------------------------

    [Theory]
    [InlineData(EncryptionMethod.Pbkdf2, 0x01)]
    [InlineData(EncryptionMethod.Argon2, 0x02)]
    [InlineData(EncryptionMethod.Rsa, 0x03)]
    [InlineData(EncryptionMethod.MLKem, 0x04)]
    public void EncryptionMethod_HasTheSpecifiedByteValue(EncryptionMethod method, byte expected) =>
        Assert.Equal(expected, (byte)method);

    /// <summary>
    /// <c>0x05</c> is reserved for the RSA + ML-KEM hybrid and must not be a defined member until
    /// that method exists — see <c>docs/format.md</c> §10.
    /// </summary>
    [Fact]
    public void EncryptionMethod_DoesNotDefineTheReservedHybridByte() =>
        Assert.False(System.Enum.IsDefined(typeof(EncryptionMethod), (EncryptionMethod)0x05));

    // --- §2.4 Cipher bytes -------------------------------------------------------------------

    [Theory]
    [InlineData(Cipher.Aes256Gcm, 0x01)]
    [InlineData(Cipher.Twofish256Gcm, 0x02)]
    [InlineData(Cipher.Serpent256Gcm, 0x03)]
    [InlineData(Cipher.Camellia256Gcm, 0x04)]
    public void Cipher_HasTheSpecifiedByteValue(Cipher cipher, byte expected) =>
        Assert.Equal(expected, (byte)cipher);

    // --- §2.3 / §4 Fixed parameters ------------------------------------------------------------

    [Fact]
    public void FormatVersion_Is0x10() => Assert.Equal(0x10, DataEncryptionDefaults.FormatVersion);

    [Fact]
    public void FixedSizes_MatchTheSpecification()
    {
        Assert.Equal(32, DataEncryptionDefaults.DataKeySizeBytes);
        Assert.Equal(12, DataEncryptionDefaults.NonceSizeBytes);
        Assert.Equal(16, DataEncryptionDefaults.SaltSizeBytes);
        Assert.Equal(128, DataEncryptionDefaults.GcmMacSizeBits);
        Assert.Equal(16, DataEncryptionDefaults.KeyConfirmationTagSizeBytes);
    }

    /// <summary>The GCM tag size must be Enigma.Core's maximum, not merely the number 128.</summary>
    [Fact]
    public void GcmMacSizeBits_IsEnigmaCoreMaxBits() =>
        Assert.Equal(Enigma.Core.Symmetric.BlockCiphers.GcmMacSize.MaxBits, DataEncryptionDefaults.GcmMacSizeBits);

    // --- §4.1 Default cost parameters ----------------------------------------------------------

    [Fact]
    public void DefaultCostParameters_MatchTheSpecification()
    {
        Assert.Equal(600_000, DataEncryptionDefaults.Pbkdf2Iterations);
        Assert.Equal(3, DataEncryptionDefaults.Argon2Iterations);
        Assert.Equal(65_536, DataEncryptionDefaults.Argon2MemorySizeKb);
        Assert.Equal(4, DataEncryptionDefaults.Argon2DegreeOfParallelism);
    }

    // --- §8 Limits -----------------------------------------------------------------------------

    [Fact]
    public void DefaultLimits_MatchTheSpecification()
    {
        DataEncryptionLimits limits = DataEncryptionLimits.Default;

        Assert.Equal(10_000_000, limits.MaxPbkdf2Iterations);
        Assert.Equal(64, limits.MaxArgon2Iterations);
        Assert.Equal(1_048_576, limits.MaxArgon2MemorySizeKb);
        Assert.Equal(64, limits.MaxArgon2DegreeOfParallelism);
        Assert.Equal(4_096, limits.MaxWrappedKeyLength);
        Assert.Equal(4_096, limits.MaxEncapsulationLength);
    }

    [Fact]
    public void DefaultLimits_AreOverridable()
    {
        var tightened = new DataEncryptionLimits { MaxArgon2MemorySizeKb = 131_072 };

        Assert.Equal(131_072, tightened.MaxArgon2MemorySizeKb);
        // Untouched bounds keep their defaults, and the shared instance is unaffected.
        Assert.Equal(64, tightened.MaxArgon2Iterations);
        Assert.Equal(1_048_576, DataEncryptionLimits.Default.MaxArgon2MemorySizeKb);
    }

    // --- §3 Header-length arithmetic -------------------------------------------------------------

    private const int CommonPrefixLength = 5; // magic (2) + method (1) + version (1) + cipher (1)

    /// <summary>
    /// The four header lengths of <c>docs/format.md</c> §3, recomputed from the constants that
    /// define them. This is the offset arithmetic the spec's tables assert; if a size constant moves,
    /// the spec's stated lengths must move with it.
    /// </summary>
    [Fact]
    public void HeaderLengths_MatchTheSpecification()
    {
        int nonce = DataEncryptionDefaults.NonceSizeBytes;
        int salt = DataEncryptionDefaults.SaltSizeBytes;
        int kcTag = DataEncryptionDefaults.KeyConfirmationTagSizeBytes;
        const int int32 = sizeof(int);

        // PBKDF2: prefix + nonce + salt + iterations + tag
        Assert.Equal(53, CommonPrefixLength + nonce + salt + int32 + kcTag);

        // Argon2: prefix + nonce + salt + iterations + parallelism + memory + tag
        Assert.Equal(61, CommonPrefixLength + nonce + salt + (3 * int32) + kcTag);

        // RSA: prefix + nonce + wrapped-key length + tag  (+ N)
        Assert.Equal(37, CommonPrefixLength + nonce + int32 + kcTag);

        // ML-KEM: prefix + parameter set + nonce + encapsulation length + tag  (+ N)
        Assert.Equal(38, CommonPrefixLength + 1 + nonce + int32 + kcTag);
    }
}
