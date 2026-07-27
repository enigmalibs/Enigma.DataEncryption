using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Cancellation of both password methods, at both of the points where it matters: before the call does
/// anything, and in the middle of the payload.
/// </summary>
/// <remarks>
/// The pre-cancelled case is more than a formality here. A password method's first real act is a
/// deliberately expensive key derivation — 600,000 PBKDF2 iterations or 64 MiB of Argon2id by default —
/// so a token that is already cancelled must be noticed <b>before</b> that, not after. The tests below
/// prove the ordering with a key-derivation factory that throws if it is reached at all.
/// </remarks>
public sealed class PasswordCancellationTests
{
    /// <summary>Both methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<PasswordMethod> Methods() => [PasswordMethod.Pbkdf2, PasswordMethod.Argon2];

    // --- Cancelled before the call ------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EncryptWithAnAlreadyCancelledTokenDerivesNothing(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method, poisonKdf: true);
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(PasswordTestData.Plaintext(1_024), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => adapter.EncryptAsync(
                input, output, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, cancelled.Token));

        Assert.Equal(0, output.Length);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EncryptWithAnAlreadyCancelledTokenIsCancelledOnTheCharOverloadToo(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method, poisonKdf: true);
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(PasswordTestData.Plaintext(1_024), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => adapter.EncryptAsync(
                input, output, Cipher.Aes256Gcm, PasswordTestData.PasswordChars(), null, cancelled.Token));
    }

    /// <summary>
    /// Decryption too: the cancellation is observed before the header is parsed, so a cancelled call does
    /// not even read the container.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task DecryptWithAnAlreadyCancelledTokenReadsNothing(PasswordMethod method)
    {
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            PasswordServiceAdapter.Create(method), PasswordTestData.Plaintext(1_024));

        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method, poisonKdf: true);
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => adapter.DecryptAsync(input, output, PasswordTestData.PasswordBytes(), null, null, cancelled.Token));

        Assert.Equal(0, input.Position);
        Assert.Equal(0, output.Length);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task DecryptWithAnAlreadyCancelledTokenIsCancelledOnTheCharOverloadToo(PasswordMethod method)
    {
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            PasswordServiceAdapter.Create(method), PasswordTestData.Plaintext(64));

        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method, poisonKdf: true);
        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => adapter.DecryptAsync(input, output, PasswordTestData.PasswordChars(), null, null, cancelled.Token));
    }

    // --- Cancelled during the payload stage ---------------------------------------------------------

    /// <summary>
    /// Cancelled from inside the payload: the token is tripped by the input stream itself, part-way
    /// through, which is the only way to show the payload stage is cancellable rather than just its
    /// entry.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EncryptIsCancellableDuringThePayload(PasswordMethod method)
    {
        const int size = 4 * 1024 * 1024;
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);

        using CancellationTokenSource cancelAfterFirstChunks = new();
        using PatternStream plaintext = new(size);
        using CancelAfterStream input = new(plaintext, 8_192, cancelAfterFirstChunks);
        using MemoryStream output = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => adapter.EncryptAsync(
                input, output, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, cancelAfterFirstChunks.Token));

        // It stopped early — the whole payload was never consumed.
        Assert.True(
            plaintext.BytesRead < size,
            $"The cancelled encryption still read all {size} input bytes.");
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task DecryptIsCancellableDuringThePayload(PasswordMethod method)
    {
        const int size = 4 * 1024 * 1024;
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);

        using PatternStream plaintext = new(size);
        using MemoryStream container = new();
        await adapter.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        container.Position = 0;
        using CancellationTokenSource cancelAfterFirstChunks = new();
        using CancelAfterStream input = new(container, adapter.HeaderLength + 8_192, cancelAfterFirstChunks);
        using MemoryStream recovered = new();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => adapter.DecryptAsync(
                input, recovered, PasswordTestData.PasswordBytes(), null, null, cancelAfterFirstChunks.Token));

        Assert.True(
            recovered.Length < size,
            $"The cancelled decryption still produced all {size} plaintext bytes.");
    }

    /// <summary>A token that is never cancelled changes nothing, of course.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ALiveTokenLetsTheOperationComplete(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(4_096);

        using CancellationTokenSource live = new();
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await adapter.EncryptAsync(
            input, container, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, live.Token);

        container.Position = 0;
        using MemoryStream recovered = new();
        await adapter.DecryptAsync(
            container, recovered, PasswordTestData.PasswordBytes(), null, null, live.Token);

        Assert.Equal(plaintext, recovered.ToArray());
    }
}
