using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The argument matrix of both password services, across all four overloads each: null streams, a null
/// or empty password, a cost parameter that is not positive, and an undefined
/// <see cref="Cipher"/> value.
/// </summary>
/// <remarks>
/// <para>
/// Two things are asserted beyond the exception type. First, the <c>paramName</c>, because a caller acts
/// on it. Second, that the rejection happens <b>before any work</b> — nothing is written to the output
/// stream and no key is derived — which is step 1 of <c>docs/format.md</c> §7.1.
/// </para>
/// <para>
/// Note that an undefined cipher raises <see cref="ArgumentOutOfRangeException"/>, which <i>is</i> an
/// <see cref="ArgumentException"/> — the type the interface's XML docs name. Both assertions below hold
/// at once.
/// </para>
/// </remarks>
public sealed class PasswordArgumentValidationTests
{
    private const Cipher UndefinedCipher = (Cipher)0x7F;

    private static Pbkdf2DataEncryptionService Pbkdf2() => new();

    private static Argon2DataEncryptionService Argon2() => new();

    private static byte[] Password() => PasswordTestData.PasswordBytes();

    private static char[] PasswordChars() => PasswordTestData.PasswordChars();

    // --- Null streams -------------------------------------------------------------------------------

    [Fact]
    public async Task Pbkdf2Encrypt_NullInput_Throws()
    {
        using MemoryStream output = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().EncryptAsync(null!, output, Cipher.Aes256Gcm, Password(), 1_000, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().EncryptAsync(null!, output, Cipher.Aes256Gcm, PasswordChars(), 1_000, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Pbkdf2Encrypt_NullOutput_Throws()
    {
        using MemoryStream input = new();

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().EncryptAsync(input, null!, Cipher.Aes256Gcm, Password(), 1_000, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().EncryptAsync(input, null!, Cipher.Aes256Gcm, PasswordChars(), 1_000, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Pbkdf2Decrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().DecryptAsync(null!, stream, Password(), null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().DecryptAsync(stream, null!, Password(), null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().DecryptAsync(null!, stream, PasswordChars(), null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().DecryptAsync(stream, null!, PasswordChars(), null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Argon2Encrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().EncryptAsync(null!, stream, Cipher.Aes256Gcm, Password(), 1, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().EncryptAsync(stream, null!, Cipher.Aes256Gcm, Password(), 1, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().EncryptAsync(null!, stream, Cipher.Aes256Gcm, PasswordChars(), 1, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().EncryptAsync(stream, null!, Cipher.Aes256Gcm, PasswordChars(), 1, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Argon2Decrypt_NullStreams_Throw()
    {
        using MemoryStream stream = new();

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().DecryptAsync(null!, stream, Password(), null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().DecryptAsync(stream, null!, Password(), null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "input",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().DecryptAsync(null!, stream, PasswordChars(), null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "output",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().DecryptAsync(stream, null!, PasswordChars(), null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    // --- The password -------------------------------------------------------------------------------

    [Fact]
    public async Task Pbkdf2_NullPassword_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().EncryptAsync(input, output, Cipher.Aes256Gcm, (byte[])null!, 1_000, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().EncryptAsync(input, output, Cipher.Aes256Gcm, (char[])null!, 1_000, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().DecryptAsync(input, output, (byte[])null!, null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Pbkdf2().DecryptAsync(input, output, (char[])null!, null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Argon2_NullPassword_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, (byte[])null!, 1, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, (char[])null!, 1, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().DecryptAsync(input, output, (byte[])null!, null, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "password",
            (await Assert.ThrowsAsync<ArgumentNullException>(
                () => Argon2().DecryptAsync(input, output, (char[])null!, null, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Fact]
    public async Task Pbkdf2_EmptyPassword_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        await AssertEmptyPassword(() => Pbkdf2().EncryptAsync(input, output, Cipher.Aes256Gcm, Array.Empty<byte>(), 1_000, null, TestContext.Current.CancellationToken));
        await AssertEmptyPassword(() => Pbkdf2().EncryptAsync(input, output, Cipher.Aes256Gcm, Array.Empty<char>(), 1_000, null, TestContext.Current.CancellationToken));
        await AssertEmptyPassword(() => Pbkdf2().DecryptAsync(input, output, Array.Empty<byte>(), null, null, TestContext.Current.CancellationToken));
        await AssertEmptyPassword(() => Pbkdf2().DecryptAsync(input, output, Array.Empty<char>(), null, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Argon2_EmptyPassword_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        await AssertEmptyPassword(() => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, Array.Empty<byte>(), 1, 1_024, 1, null, TestContext.Current.CancellationToken));
        await AssertEmptyPassword(() => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, Array.Empty<char>(), 1, 1_024, 1, null, TestContext.Current.CancellationToken));
        await AssertEmptyPassword(() => Argon2().DecryptAsync(input, output, Array.Empty<byte>(), null, null, TestContext.Current.CancellationToken));
        await AssertEmptyPassword(() => Argon2().DecryptAsync(input, output, Array.Empty<char>(), null, null, TestContext.Current.CancellationToken));
    }

    // --- The cipher ---------------------------------------------------------------------------------

    [Fact]
    public async Task Pbkdf2Encrypt_UndefinedCipher_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        await AssertUndefinedCipher(() => Pbkdf2().EncryptAsync(input, output, UndefinedCipher, Password(), 1_000, null, TestContext.Current.CancellationToken));
        await AssertUndefinedCipher(() => Pbkdf2().EncryptAsync(input, output, UndefinedCipher, PasswordChars(), 1_000, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Argon2Encrypt_UndefinedCipher_Throws()
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        await AssertUndefinedCipher(() => Argon2().EncryptAsync(input, output, UndefinedCipher, Password(), 1, 1_024, 1, null, TestContext.Current.CancellationToken));
        await AssertUndefinedCipher(() => Argon2().EncryptAsync(input, output, UndefinedCipher, PasswordChars(), 1, 1_024, 1, null, TestContext.Current.CancellationToken));
    }

    // --- The cost parameters ------------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public async Task Pbkdf2Encrypt_IterationsNotPositive_Throws(int iterations)
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "iterations",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => Pbkdf2().EncryptAsync(input, output, Cipher.Aes256Gcm, Password(), iterations, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "iterations",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => Pbkdf2().EncryptAsync(input, output, Cipher.Aes256Gcm, PasswordChars(), iterations, null, TestContext.Current.CancellationToken))).ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public async Task Argon2Encrypt_CostParametersNotPositive_Throw(int bad)
    {
        using MemoryStream input = new();
        using MemoryStream output = new();

        Assert.Equal(
            "iterations",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, Password(), bad, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "memorySizeKb",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, Password(), 1, bad, 1, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "degreeOfParallelism",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, Password(), 1, 1_024, bad, null, TestContext.Current.CancellationToken))).ParamName);

        Assert.Equal(
            "iterations",
            (await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
                () => Argon2().EncryptAsync(input, output, Cipher.Aes256Gcm, PasswordChars(), bad, 1_024, 1, null, TestContext.Current.CancellationToken))).ParamName);
    }

    // --- Nothing happens before validation ----------------------------------------------------------

    /// <summary>
    /// A rejected call writes nothing and derives nothing: the output stream is untouched, and the
    /// poisoned key-derivation factory — which throws the moment it is used — is never reached.
    /// </summary>
    [Theory]
    [InlineData(PasswordMethod.Pbkdf2)]
    [InlineData(PasswordMethod.Argon2)]
    public async Task ARejectedCallWritesNothingAndDerivesNothing(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method, poisonKdf: true);
        using MemoryStream input = new(PasswordTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => adapter.EncryptAsync(input, output, Cipher.Aes256Gcm, Array.Empty<byte>(), null, TestContext.Current.CancellationToken));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => adapter.EncryptAsync(input, output, UndefinedCipher, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken));

        Assert.Equal(0, output.Length);
        Assert.Equal(0, input.Position);
    }

    private static async Task AssertEmptyPassword(Func<Task> operation)
    {
        ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(operation);

        Assert.Equal("password", exception.ParamName);
    }

    private static async Task AssertUndefinedCipher(Func<Task> operation)
    {
        ArgumentOutOfRangeException exception = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(operation);

        Assert.Equal("cipher", exception.ParamName);

        // The interface's XML docs name ArgumentException for this case; ArgumentOutOfRangeException is
        // one, so a caller catching either is satisfied.
        Assert.IsAssignableFrom<ArgumentException>(exception);
    }
}
