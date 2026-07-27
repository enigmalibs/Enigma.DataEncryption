using System;
using System.Linq;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Covers <see cref="RandomSource"/>, the production <see cref="IRandomSource"/> over Enigma.Core's
/// <c>RandomUtils</c>.
/// </summary>
/// <remarks>
/// This is not a test of the underlying CSPRNG's quality — that is Enigma.Core's to make. What is tested
/// here is the contract the four services rely on: the requested number of bytes come back, and
/// successive calls do not return the same bytes.
/// </remarks>
public sealed class RandomSourceTests
{
    private static readonly IRandomSource Source = new RandomSource();

    [Theory]
    [InlineData(1)]
    [InlineData(DataEncryptionDefaults.NonceSizeBytes)]
    [InlineData(DataEncryptionDefaults.SaltSizeBytes)]
    [InlineData(DataEncryptionDefaults.DataKeySizeBytes)]
    [InlineData(1024)]
    public void GenerateRandomBytes_ReturnsTheRequestedNumberOfBytes(int size) =>
        Assert.Equal(size, Source.GenerateRandomBytes(size).Length);

    [Fact]
    public void GenerateRandomBytes_ReturnsADifferentValueEachCall()
    {
        // 32 draws of 32 bytes colliding by chance is a 2^-256 event per pair; a repeat means the
        // source is not drawing fresh bytes.
        string[] draws = Enumerable
            .Range(0, 32)
            .Select(_ => Convert.ToBase64String(Source.GenerateRandomBytes(DataEncryptionDefaults.DataKeySizeBytes)))
            .ToArray();

        Assert.Equal(draws.Length, draws.Distinct().Count());
    }

    [Fact]
    public void GenerateRandomBytes_ReturnsANewArrayEachCall()
    {
        byte[] first = Source.GenerateRandomBytes(DataEncryptionDefaults.NonceSizeBytes);
        byte[] second = Source.GenerateRandomBytes(DataEncryptionDefaults.NonceSizeBytes);

        // The services clear their buffers in place, so a shared array would corrupt the next call.
        Assert.NotSame(first, second);
    }

    /// <summary>A 32-byte draw must not come back all zeroes — the failure mode of a stubbed RNG.</summary>
    [Fact]
    public void GenerateRandomBytes_DoesNotReturnAllZeroes() =>
        Assert.Contains(
            Source.GenerateRandomBytes(DataEncryptionDefaults.DataKeySizeBytes),
            b => b != 0x00);
}
