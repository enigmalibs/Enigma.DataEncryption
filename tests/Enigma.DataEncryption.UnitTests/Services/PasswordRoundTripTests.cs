using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Round-trips the two password methods across every cipher and payload shape, and asserts the
/// stream-level promises the XML docs make: nothing is disposed, nothing needs to be seekable, progress
/// counts payload bytes only, and the <see cref="char"/> overloads behave exactly like the
/// <see cref="byte"/> ones.
/// </summary>
public sealed class PasswordRoundTripTests
{
    /// <summary>Both methods against all four ciphers — the eight combinations of the plan.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<PasswordMethod, Cipher> MethodsAndCiphers()
    {
        TheoryData<PasswordMethod, Cipher> data = [];
        foreach (PasswordMethod method in new[] { PasswordMethod.Pbkdf2, PasswordMethod.Argon2 })
        {
            foreach (Cipher cipher in new[]
                     {
                         Cipher.Aes256Gcm, Cipher.Twofish256Gcm, Cipher.Serpent256Gcm, Cipher.Camellia256Gcm,
                     })
            {
                data.Add(method, cipher);
            }
        }

        return data;
    }

    /// <summary>Both methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<PasswordMethod> Methods() => [PasswordMethod.Pbkdf2, PasswordMethod.Argon2];

    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task RoundTripsExactly(PasswordMethod method, Cipher cipher)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(4_096 + 17);

        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, plaintext, cipher);
        byte[] recovered = await PasswordTestData.DecryptToBytesAsync(adapter, container);

        Assert.Equal(plaintext, recovered);
    }

    /// <summary>
    /// The container is exactly the header, the ciphertext and the 128-bit GCM tag — no padding, no
    /// trailer (<c>docs/format.md</c> §4).
    /// </summary>
    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task TheContainerIsHeaderPlusCiphertextPlusTag(PasswordMethod method, Cipher cipher)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(1_000);

        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, plaintext, cipher);

        Assert.Equal(adapter.HeaderLength + plaintext.Length + 16, container.Length);
        Assert.Equal((byte)adapter.Method, container[2]);
        Assert.Equal((byte)cipher, container[4]);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task RoundTripsAnEmptyPayload(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);

        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, []);
        Assert.Equal(adapter.HeaderLength + 16, container.Length);

        byte[] recovered = await PasswordTestData.DecryptToBytesAsync(adapter, container);
        Assert.Empty(recovered);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task RoundTripsASinglePayloadByte(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);

        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, [0x5A]);
        byte[] recovered = await PasswordTestData.DecryptToBytesAsync(adapter, container);

        Assert.Equal<byte[]>([0x5A], recovered);
    }

    // --- Large payload, and evidence that it streams -------------------------------------------------

    /// <summary>
    /// An 8 MiB payload, generated rather than materialized, round-tripped and verified byte by byte as
    /// it arrives.
    /// </summary>
    /// <remarks>
    /// The plaintext never exists as an array on either side of the round trip, which is itself part of
    /// the assertion: an implementation that buffered the payload could not satisfy this test's memory
    /// profile, and <see cref="StreamsRatherThanBufferingTheWholePayload"/> pins the interleaving
    /// directly.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task RoundTripsALargePayload(PasswordMethod method)
    {
        const int size = 8 * 1024 * 1024;
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);

        using PatternStream plaintext = new(size);
        using MemoryStream container = new();
        await adapter.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        Assert.Equal(adapter.HeaderLength + size + 16, container.Length);

        container.Position = 0;
        using PatternVerifyingStream recovered = new();
        await adapter.DecryptAsync(
            container, recovered, PasswordTestData.PasswordBytes(), null, null, TestContext.Current.CancellationToken);

        Assert.Equal(size, recovered.BytesWritten);
    }

    /// <summary>
    /// The payload is streamed, not buffered: ciphertext reaches the output while the input still has
    /// bytes left to give.
    /// </summary>
    /// <remarks>
    /// The check is an interleaving one — how many payload bytes had been read when the first payload
    /// byte was written — because that is the observable difference between streaming and
    /// read-it-all-then-write-it-all, and it does not depend on any particular buffer size.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task StreamsRatherThanBufferingTheWholePayload(PasswordMethod method)
    {
        const int size = 8 * 1024 * 1024;
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);

        using PatternStream plaintext = new(size);
        long readWhenFirstPayloadByteWasWritten = -1;
        using CountingSink container = new(adapter.HeaderLength, () => readWhenFirstPayloadByteWasWritten = plaintext.BytesRead);

        await adapter.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        Assert.True(
            readWhenFirstPayloadByteWasWritten is > 0 and < size,
            $"The first payload write happened after {readWhenFirstPayloadByteWasWritten} of {size} input bytes had been read; a streaming implementation writes before the input is exhausted.");
    }

    // --- Stream contract ----------------------------------------------------------------------------

    /// <summary>Decryption must not require a seekable stream (<c>docs/format.md</c> §7.2).</summary>
    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task DecryptsFromANonSeekableDripFedStream(PasswordMethod method, Cipher cipher)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(300);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, plaintext, cipher);

        using ForwardOnlyStream input = new(container);
        using MemoryStream output = new();
        await adapter.DecryptAsync(
            input, output, PasswordTestData.PasswordBytes(), null, null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, output.ToArray());
    }

    /// <summary>Neither stream is disposed, and the caller's position is left where the operation ended.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task NeitherStreamIsDisposed(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await adapter.EncryptAsync(
            input, container, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        // A disposed MemoryStream throws on these; a live one does not.
        Assert.True(input.CanRead);
        Assert.True(container.CanWrite);
        Assert.Equal(container.Length, container.Position);

        container.Position = 0;
        using MemoryStream output = new();
        await adapter.DecryptAsync(
            container, output, PasswordTestData.PasswordBytes(), null, null, TestContext.Current.CancellationToken);

        Assert.True(container.CanRead);
        Assert.True(output.CanWrite);
    }

    /// <summary>
    /// The container is written at the output stream's current position, not at its start — so a caller
    /// may prepend their own framing.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task WritesAtTheOutputStreamsCurrentPosition(PasswordMethod method)
    {
        byte[] preamble = [0xDE, 0xAD, 0xBE, 0xEF];
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(48);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await output.WriteAsync(preamble, 0, preamble.Length, TestContext.Current.CancellationToken);
        await adapter.EncryptAsync(
            input, output, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        byte[] written = output.ToArray();
        Assert.Equal(preamble, written[..4]);
        Assert.Equal(0xEC, written[4]);

        // …and it decrypts from that offset just as well.
        output.Position = preamble.Length;
        using MemoryStream recovered = new();
        await adapter.DecryptAsync(
            output, recovered, PasswordTestData.PasswordBytes(), null, null, TestContext.Current.CancellationToken);
        Assert.Equal(plaintext, recovered.ToArray());
    }

    // --- Progress -----------------------------------------------------------------------------------

    /// <summary>
    /// Progress totals the payload byte count and excludes the header, on both directions.
    /// </summary>
    /// <remarks>
    /// Enigma.Core reports <b>per-chunk increments</b> rather than a running total, so the property to
    /// assert is that every report is positive — which makes the cumulative total non-decreasing — and
    /// that the reports sum to the payload length exactly. Were the header counted, the sum would be
    /// larger by 53 or 61.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ProgressTotalsThePayloadBytesAndExcludesTheHeader(PasswordMethod method)
    {
        const int size = 10_000;
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(size);

        ProgressCollector encryptProgress = new();
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await adapter.EncryptAsync(
            input, container, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), encryptProgress, TestContext.Current.CancellationToken);

        Assert.NotEmpty(encryptProgress.Values);
        Assert.All(encryptProgress.Values, value => Assert.True(value > 0, $"Progress reported {value}."));
        Assert.Equal(size, encryptProgress.Total);
        AssertCumulativeTotalIsNonDecreasing(encryptProgress.Values);

        ProgressCollector decryptProgress = new();
        container.Position = 0;
        using MemoryStream output = new();
        await adapter.DecryptAsync(
            container, output, PasswordTestData.PasswordBytes(), null, decryptProgress, TestContext.Current.CancellationToken);

        Assert.NotEmpty(decryptProgress.Values);
        Assert.Equal(size, decryptProgress.Total);
        AssertCumulativeTotalIsNonDecreasing(decryptProgress.Values);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ProgressIsOptional(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(32);

        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, plaintext);

        Assert.Equal(plaintext, await PasswordTestData.DecryptToBytesAsync(adapter, container));
    }

    // --- char[] overloads ---------------------------------------------------------------------------

    /// <summary>
    /// The <see cref="char"/> overload is the <see cref="byte"/> overload over the UTF-8 encoding of the
    /// same password — byte-identical output, given the same salt and nonce.
    /// </summary>
    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task TheCharOverloadProducesIdenticalBytes(PasswordMethod method, Cipher cipher)
    {
        byte[] plaintext = PasswordTestData.Plaintext(200);

        using MemoryStream fromBytesInput = new(plaintext, writable: false);
        using MemoryStream fromBytes = new();
        await PasswordTestData.Deterministic(method).EncryptAsync(
            fromBytesInput, fromBytes, cipher, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        using MemoryStream fromCharsInput = new(plaintext, writable: false);
        using MemoryStream fromChars = new();
        await PasswordTestData.Deterministic(method).EncryptAsync(
            fromCharsInput, fromChars, cipher, PasswordTestData.PasswordChars(), null, TestContext.Current.CancellationToken);

        Assert.Equal(fromBytes.ToArray(), fromChars.ToArray());
    }

    /// <summary>A container written under the byte overload opens under the char overload, and vice versa.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheTwoOverloadsAreInterchangeable(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(128);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await adapter.EncryptAsync(
            input, container, Cipher.Aes256Gcm, PasswordTestData.PasswordChars(), null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, await PasswordTestData.DecryptToBytesAsync(adapter, container.ToArray()));

        container.Position = 0;
        using MemoryStream recovered = new();
        await adapter.DecryptAsync(
            container, recovered, PasswordTestData.PasswordChars(), null, null, TestContext.Current.CancellationToken);
        Assert.Equal(plaintext, recovered.ToArray());
    }

    /// <summary>
    /// The caller's arrays survive the call: the temporary UTF-8 buffer is the library's to clear, the
    /// caller's password is not.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheCallersPasswordArraysAreNeverMutated(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(64);
        char[] chars = PasswordTestData.PasswordChars();
        byte[] bytes = PasswordTestData.PasswordBytes();

        using MemoryStream charInput = new(plaintext, writable: false);
        using MemoryStream charContainer = new();
        await adapter.EncryptAsync(
            charInput, charContainer, Cipher.Aes256Gcm, chars, null, TestContext.Current.CancellationToken);
        Assert.Equal(PasswordTestData.PasswordChars(), chars);

        using MemoryStream byteInput = new(plaintext, writable: false);
        using MemoryStream byteContainer = new();
        await adapter.EncryptAsync(
            byteInput, byteContainer, Cipher.Aes256Gcm, bytes, null, TestContext.Current.CancellationToken);
        Assert.Equal(PasswordTestData.PasswordBytes(), bytes);

        // And on the way back, where the same buffers are used again.
        charContainer.Position = 0;
        using MemoryStream charRecovered = new();
        await adapter.DecryptAsync(
            charContainer, charRecovered, chars, null, null, TestContext.Current.CancellationToken);
        Assert.Equal(PasswordTestData.PasswordChars(), chars);

        byteContainer.Position = 0;
        using MemoryStream byteRecovered = new();
        await adapter.DecryptAsync(
            byteContainer, byteRecovered, bytes, null, null, TestContext.Current.CancellationToken);
        Assert.Equal(PasswordTestData.PasswordBytes(), bytes);
    }

    /// <summary>A non-ASCII password round-trips — the UTF-8 encoding is applied on both sides.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ANonAsciiPasswordRoundTrips(PasswordMethod method)
    {
        char[] password = "pässwörd-🔐-日本語".ToCharArray();
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(96);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await adapter.EncryptAsync(
            input, container, Cipher.Aes256Gcm, password, null, TestContext.Current.CancellationToken);

        container.Position = 0;
        using MemoryStream recovered = new();
        await adapter.DecryptAsync(
            container, recovered, password, null, null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, recovered.ToArray());
    }

    // --- Salt and nonce -----------------------------------------------------------------------------

    /// <summary>
    /// A fresh salt and nonce per call: two encryptions of the same plaintext under the same password
    /// must not produce the same container. Nonce reuse under one key is the classic GCM catastrophe.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EachCallDrawsAFreshSaltAndNonce(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(64);

        byte[] first = await PasswordTestData.EncryptToBytesAsync(adapter, plaintext);
        byte[] second = await PasswordTestData.EncryptToBytesAsync(adapter, plaintext);

        Assert.NotEqual(first, second);
        Assert.NotEqual(first[5..17], second[5..17]);   // nonce
        Assert.NotEqual(first[17..33], second[17..33]); // salt
    }

    /// <summary>The salt and nonce come from the injected source, one of each, at the specified sizes.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheSaltAndNonceComeFromTheRandomSource(PasswordMethod method)
    {
        FixedRandomSource randomSource = new(FormatTestData.Salt(), FormatTestData.Nonce());
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method, randomSource);

        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(16));

        Assert.Equal(FormatTestData.Nonce(), container[5..17]);
        Assert.Equal(FormatTestData.Salt(), container[17..33]);
        Assert.Equal(1, randomSource.Requests[DataEncryptionDefaults.SaltSizeBytes]);
        Assert.Equal(1, randomSource.Requests[DataEncryptionDefaults.NonceSizeBytes]);
    }

    private static void AssertCumulativeTotalIsNonDecreasing(IReadOnlyList<int> values)
    {
        long total = 0;
        foreach (int value in values)
        {
            long next = total + value;
            Assert.True(next >= total, $"The cumulative progress total fell from {total} to {next}.");
            total = next;
        }
    }

    /// <summary>
    /// A write-only sink that counts, and calls back the first time a byte is written past the header.
    /// </summary>
    private sealed class CountingSink(int headerLength, Action onFirstPayloadWrite) : Stream
    {
        private long _written;
        private bool _notified;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => _written;

        public override long Position
        {
            get => _written;
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _written += count;
            if (!_notified && _written > headerLength)
            {
                _notified = true;
                onFirstPayloadWrite();
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
