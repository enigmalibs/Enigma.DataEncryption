using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Covers <see cref="LimitsValidator"/> against every bound in <c>docs/format.md</c> §8: the cap value
/// itself is accepted, one over it is rejected, and so are zero and negative.
/// </summary>
public sealed class LimitsValidatorTests
{
    private static readonly DataEncryptionLimits Limits = DataEncryptionLimits.Default;

    // --- PBKDF2 iterations -----------------------------------------------------------------------

    [Fact]
    public void Pbkdf2Iterations_AtTheCap_IsAccepted() =>
        LimitsValidator.ValidatePbkdf2Iterations(Limits.MaxPbkdf2Iterations, Limits);

    [Theory]
    [InlineData(1)]
    [InlineData(600_000)]
    public void Pbkdf2Iterations_WithinTheCap_IsAccepted(int iterations) =>
        LimitsValidator.ValidatePbkdf2Iterations(iterations, Limits);

    [Fact]
    public void Pbkdf2Iterations_OneOverTheCap_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidatePbkdf2Iterations(Limits.MaxPbkdf2Iterations + 1, Limits));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Pbkdf2Iterations_ZeroOrNegative_IsRejected(int iterations) =>
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidatePbkdf2Iterations(iterations, Limits));

    [Fact]
    public void Pbkdf2Iterations_IntMaxValue_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidatePbkdf2Iterations(int.MaxValue, Limits));

    // --- Argon2: three fields, each bounded independently ----------------------------------------

    [Fact]
    public void Argon2_AtEveryCap_IsAccepted() =>
        LimitsValidator.ValidateArgon2(
            Limits.MaxArgon2Iterations,
            Limits.MaxArgon2DegreeOfParallelism,
            Limits.MaxArgon2MemorySizeKb,
            Limits);

    [Fact]
    public void Argon2_WithTheDefaultCosts_IsAccepted() =>
        LimitsValidator.ValidateArgon2(
            DataEncryptionDefaults.Argon2Iterations,
            DataEncryptionDefaults.Argon2DegreeOfParallelism,
            DataEncryptionDefaults.Argon2MemorySizeKb,
            Limits);

    [Fact]
    public void Argon2Iterations_OneOverTheCap_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(() => LimitsValidator.ValidateArgon2(
            Limits.MaxArgon2Iterations + 1,
            DataEncryptionDefaults.Argon2DegreeOfParallelism,
            DataEncryptionDefaults.Argon2MemorySizeKb,
            Limits));

    [Fact]
    public void Argon2DegreeOfParallelism_OneOverTheCap_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(() => LimitsValidator.ValidateArgon2(
            DataEncryptionDefaults.Argon2Iterations,
            Limits.MaxArgon2DegreeOfParallelism + 1,
            DataEncryptionDefaults.Argon2MemorySizeKb,
            Limits));

    [Fact]
    public void Argon2MemorySizeKb_OneOverTheCap_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(() => LimitsValidator.ValidateArgon2(
            DataEncryptionDefaults.Argon2Iterations,
            DataEncryptionDefaults.Argon2DegreeOfParallelism,
            Limits.MaxArgon2MemorySizeKb + 1,
            Limits));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Argon2Iterations_ZeroOrNegative_IsRejected(int iterations) =>
        Assert.Throws<DataEncryptionFormatException>(() => LimitsValidator.ValidateArgon2(
            iterations,
            DataEncryptionDefaults.Argon2DegreeOfParallelism,
            DataEncryptionDefaults.Argon2MemorySizeKb,
            Limits));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Argon2DegreeOfParallelism_ZeroOrNegative_IsRejected(int degreeOfParallelism) =>
        Assert.Throws<DataEncryptionFormatException>(() => LimitsValidator.ValidateArgon2(
            DataEncryptionDefaults.Argon2Iterations,
            degreeOfParallelism,
            DataEncryptionDefaults.Argon2MemorySizeKb,
            Limits));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Argon2MemorySizeKb_ZeroOrNegative_IsRejected(int memorySizeKb) =>
        Assert.Throws<DataEncryptionFormatException>(() => LimitsValidator.ValidateArgon2(
            DataEncryptionDefaults.Argon2Iterations,
            DataEncryptionDefaults.Argon2DegreeOfParallelism,
            memorySizeKb,
            Limits));

    /// <summary>
    /// An Argon2 header claiming a terabyte of memory is exactly the denial-of-service the caps exist
    /// to stop, and it is stopped by arithmetic — nothing here allocates.
    /// </summary>
    [Fact]
    public void Argon2MemorySizeKb_OfOneTebibyte_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(() => LimitsValidator.ValidateArgon2(
            DataEncryptionDefaults.Argon2Iterations,
            DataEncryptionDefaults.Argon2DegreeOfParallelism,
            1_073_741_824,
            Limits));

    // --- RSA wrapped-key length -------------------------------------------------------------------

    [Fact]
    public void WrappedKeyLength_AtTheCap_IsAccepted() =>
        LimitsValidator.ValidateWrappedKeyLength(Limits.MaxWrappedKeyLength, Limits);

    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(512)]
    public void WrappedKeyLength_OfARealRsaModulus_IsAccepted(int length) =>
        LimitsValidator.ValidateWrappedKeyLength(length, Limits);

    [Fact]
    public void WrappedKeyLength_OneOverTheCap_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateWrappedKeyLength(Limits.MaxWrappedKeyLength + 1, Limits));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    public void WrappedKeyLength_OutOfRange_IsRejected(int length) =>
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateWrappedKeyLength(length, Limits));

    // --- ML-KEM encapsulation length --------------------------------------------------------------

    [Fact]
    public void EncapsulationLength_AtTheCap_IsAccepted() =>
        LimitsValidator.ValidateEncapsulationLength(Limits.MaxEncapsulationLength, Limits);

    [Theory]
    [InlineData(768)]
    [InlineData(1088)]
    [InlineData(1568)]
    public void EncapsulationLength_OfARealParameterSet_IsAccepted(int length) =>
        LimitsValidator.ValidateEncapsulationLength(length, Limits);

    [Fact]
    public void EncapsulationLength_OneOverTheCap_IsRejected() =>
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateEncapsulationLength(Limits.MaxEncapsulationLength + 1, Limits));

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    public void EncapsulationLength_OutOfRange_IsRejected(int length) =>
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateEncapsulationLength(length, Limits));

    // --- Tightened limits -------------------------------------------------------------------------

    /// <summary>A caller-supplied instance must be the bound that is actually applied.</summary>
    [Fact]
    public void TightenedLimits_AreTheOnesApplied()
    {
        DataEncryptionLimits tightened = new() { MaxPbkdf2Iterations = 100 };

        LimitsValidator.ValidatePbkdf2Iterations(100, tightened);
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidatePbkdf2Iterations(101, tightened));

        // …and the default instance is unaffected by it.
        LimitsValidator.ValidatePbkdf2Iterations(101, DataEncryptionLimits.Default);
    }

    /// <summary>
    /// Each of the three Argon2 caps is tightenable on its own, and each is applied independently. Argon2
    /// is the method where that matters: a caller who can afford 64 MiB but not 64 passes needs to say so
    /// without also lowering the memory bound.
    /// </summary>
    [Fact]
    public void EachArgon2CapCanBeTightenedIndependently()
    {
        DataEncryptionLimits fewerPasses = new() { MaxArgon2Iterations = 2 };
        LimitsValidator.ValidateArgon2(2, 4, 65_536, fewerPasses);
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateArgon2(3, 4, 65_536, fewerPasses));

        DataEncryptionLimits fewerLanes = new() { MaxArgon2DegreeOfParallelism = 2 };
        LimitsValidator.ValidateArgon2(3, 2, 65_536, fewerLanes);
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateArgon2(3, 3, 65_536, fewerLanes));

        DataEncryptionLimits lessMemory = new() { MaxArgon2MemorySizeKb = 1_024 };
        LimitsValidator.ValidateArgon2(3, 4, 1_024, lessMemory);
        Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateArgon2(3, 4, 1_025, lessMemory));

        // Tightening one cap leaves the other two at their defaults, so the default costs still pass.
        LimitsValidator.ValidateArgon2(
            DataEncryptionDefaults.Argon2Iterations,
            DataEncryptionDefaults.Argon2DegreeOfParallelism,
            DataEncryptionDefaults.Argon2MemorySizeKb,
            new DataEncryptionLimits { MaxArgon2Iterations = 3 });
    }

    /// <summary>The message must name the field and the cap, or a caller cannot act on it.</summary>
    [Fact]
    public void TheMessage_NamesTheFieldAndTheCap()
    {
        DataEncryptionFormatException exception = Assert.Throws<DataEncryptionFormatException>(
            () => LimitsValidator.ValidateArgon2(
                DataEncryptionDefaults.Argon2Iterations,
                DataEncryptionDefaults.Argon2DegreeOfParallelism,
                Limits.MaxArgon2MemorySizeKb + 1,
                Limits));

        Assert.Contains("Argon2 memory size in KiB", exception.Message);
        Assert.Contains(Limits.MaxArgon2MemorySizeKb.ToString(), exception.Message);
    }
}
