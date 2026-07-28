using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// Covers <see cref="CipherResolver"/>, including the deliberate split between an undefined cipher
/// that arrived in a header (a format error) and one a caller passed (an argument error).
/// </summary>
public sealed class CipherResolverTests
{
    private static readonly IBlockCipherServiceFactory Factory = new BlockCipherServiceFactory();

    [Theory]
    [InlineData(Cipher.Aes256Gcm)]
    [InlineData(Cipher.Twofish256Gcm)]
    [InlineData(Cipher.Serpent256Gcm)]
    [InlineData(Cipher.Camellia256Gcm)]
    public void Resolve_MapsEveryDefinedCipherToANonNullService(Cipher cipher) =>
        Assert.NotNull(CipherResolver.Resolve(Factory, cipher));

    /// <summary>
    /// The four ciphers must map to four <i>different</i> algorithms, not all to AES.
    /// </summary>
    /// <remarks>
    /// Asserted behaviourally, because Enigma.Core returns the same concrete service type for every
    /// cipher — the algorithm is configuration, not a distinct class, so comparing
    /// <see cref="object.GetType"/> would prove nothing. Four ciphertexts over the same key, nonce and
    /// plaintext must differ pairwise; a resolver that returned AES for every value would produce four
    /// identical ones and round-trip perfectly while writing containers no conforming reader could
    /// decrypt.
    /// </remarks>
    [Fact]
    public async Task Resolve_MapsTheFourCiphersToFourDistinctAlgorithms()
    {
        Cipher[] ciphers = [Cipher.Aes256Gcm, Cipher.Twofish256Gcm, Cipher.Serpent256Gcm, Cipher.Camellia256Gcm];
        string[] ciphertexts = new string[ciphers.Length];

        for (int i = 0; i < ciphers.Length; i++)
        {
            ciphertexts[i] = Convert.ToBase64String(await EncryptFixedPlaintextAsync(ciphers[i]));
        }

        Assert.Equal(ciphers.Length, ciphertexts.Distinct().Count());
    }

    private static async Task<byte[]> EncryptFixedPlaintextAsync(Cipher cipher)
    {
        using MemoryStream input = new(FormatTestData.Sequence(0xA0, 32), writable: false);
        using MemoryStream output = new();

        await CipherResolver.Resolve(Factory, cipher).EncryptAsync(
            input,
            output,
            FormatTestData.DataKey(),
            FormatTestData.Nonce(),
            BlockCipherMode.Gcm,
            PaddingScheme.None,
            DataEncryptionDefaults.GcmMacSizeBits,
            associatedData: null,
            progress: null,
            cancellationToken: TestContext.Current.CancellationToken);

        return output.ToArray();
    }

    [Fact]
    public void Resolve_ThrowsFormat_ForAnUndefinedCipher() =>
        Assert.Throws<DataEncryptionFormatException>(() => CipherResolver.Resolve(Factory, (Cipher)0x09));

    // --- The header path ------------------------------------------------------------------------

    [Theory]
    [InlineData(0x01, Cipher.Aes256Gcm)]
    [InlineData(0x02, Cipher.Twofish256Gcm)]
    [InlineData(0x03, Cipher.Serpent256Gcm)]
    [InlineData(0x04, Cipher.Camellia256Gcm)]
    public void FromHeaderByte_MapsTheSpecifiedBytes(byte value, Cipher expected) =>
        Assert.Equal(expected, CipherResolver.FromHeaderByte(value));

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x05)]
    [InlineData(0x10)]
    [InlineData(0xFF)]
    public void FromHeaderByte_ThrowsFormat_ForAnUndefinedByte(byte value) =>
        Assert.Throws<DataEncryptionFormatException>(() => CipherResolver.FromHeaderByte(value));

    // --- The caller path ------------------------------------------------------------------------

    [Theory]
    [InlineData(Cipher.Aes256Gcm)]
    [InlineData(Cipher.Twofish256Gcm)]
    [InlineData(Cipher.Serpent256Gcm)]
    [InlineData(Cipher.Camellia256Gcm)]
    public void ValidateArgument_Accepts_EveryDefinedCipher(Cipher cipher) =>
        CipherResolver.ValidateArgument(cipher, "cipher");

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x05)]
    [InlineData(0xFF)]
    public void ValidateArgument_ThrowsArgumentOutOfRange_ForAnUndefinedCipher(byte value)
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => CipherResolver.ValidateArgument((Cipher)value, "cipher"));

        Assert.Equal("cipher", exception.ParamName);
    }

    /// <summary>
    /// The distinction is the point: the same undefined value is a format error from a header and an
    /// argument error from a caller. Neither path may borrow the other's exception type.
    /// </summary>
    [Fact]
    public void TheTwoPathsRaiseDifferentExceptionTypes_ForTheSameUndefinedValue()
    {
        Assert.Throws<DataEncryptionFormatException>(() => CipherResolver.FromHeaderByte(0x09));
        Assert.Throws<ArgumentOutOfRangeException>(() => CipherResolver.ValidateArgument((Cipher)0x09, "cipher"));
    }
}
