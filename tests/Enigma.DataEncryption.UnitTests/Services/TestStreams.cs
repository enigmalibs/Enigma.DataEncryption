using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// A container stream whose header reads normally and whose payload cannot be read at all.
/// </summary>
/// <remarks>
/// This is how "the wrong password fails at key confirmation, before a single payload byte is read"
/// (<c>docs/format.md</c> §6.2) is proved rather than asserted: if the implementation ever reached the
/// payload, the failure would be this stream's <see cref="IOException"/> instead of the expected
/// <see cref="DataDecryptionException"/>.
/// </remarks>
/// <param name="header">The header bytes to serve.</param>
internal sealed class PoisonedPayloadStream(byte[] header) : Stream
{
    private int _position;

    /// <summary>Whether anything past the header was requested.</summary>
    internal bool PayloadWasRead { get; private set; }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_position >= header.Length)
        {
            PayloadWasRead = true;
            throw new IOException("The payload must not be read: key confirmation should have failed first.");
        }

        int available = Math.Min(count, header.Length - _position);
        Buffer.BlockCopy(header, _position, buffer, offset, available);
        _position += available;
        return available;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        Task.FromResult(Read(buffer, offset, count));

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// A forward-only stream over a byte array that reports itself unseekable and never returns more than
/// <paramref name="maxChunk"/> bytes per read.
/// </summary>
/// <remarks>
/// Decryption must not require a seekable stream (<c>docs/format.md</c> §7.2), and short reads must be
/// handled correctly — the drip feed exercises both.
/// </remarks>
/// <param name="content">The bytes to serve.</param>
/// <param name="maxChunk">The most bytes to return from one read.</param>
internal sealed class ForwardOnlyStream(byte[] content, int maxChunk = 1) : Stream
{
    private int _position;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (count == 0 || _position >= content.Length) return 0;

        int available = Math.Min(Math.Min(count, maxChunk), content.Length - _position);
        Buffer.BlockCopy(content, _position, buffer, offset, available);
        _position += available;
        return available;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        Task.FromResult(Read(buffer, offset, count));

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// A generated, non-seekable source of <paramref name="length"/> deterministic bytes — a large payload
/// that never exists as an array.
/// </summary>
/// <remarks>
/// The large-payload tests are meant to demonstrate that the library streams; materializing 8 MiB in the
/// test to check it would rather undercut the point.
/// </remarks>
/// <param name="length">How many bytes to produce.</param>
internal sealed class PatternStream(long length) : Stream
{
    private long _position;

    /// <summary>The byte this pattern holds at a given offset.</summary>
    /// <param name="offset">The offset into the pattern.</param>
    /// <returns>The byte value.</returns>
    internal static byte ByteAt(long offset) => (byte)((offset * 31) + 7);

    /// <summary>How many bytes have been produced so far.</summary>
    internal long BytesRead => _position;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int produced = (int)Math.Min(count, length - _position);
        for (int i = 0; i < produced; i++)
        {
            buffer[offset + i] = ByteAt(_position + i);
        }

        _position += produced;
        return produced;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        Task.FromResult(Read(buffer, offset, count));

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

/// <summary>
/// A write-only sink that checks every byte it receives against <see cref="PatternStream"/> and counts
/// them, so a large round-trip can be verified without holding the plaintext twice.
/// </summary>
internal sealed class PatternVerifyingStream : Stream
{
    private long _position;

    /// <summary>How many bytes were written.</summary>
    internal long BytesWritten => _position;

    public override bool CanRead => false;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => _position;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        for (int i = 0; i < count; i++)
        {
            byte expected = PatternStream.ByteAt(_position + i);
            if (buffer[offset + i] != expected)
            {
                Assert.Fail(
                    $"Recovered byte at offset {_position + i} is 0x{buffer[offset + i]:X2}; expected 0x{expected:X2}.");
            }
        }

        _position += count;
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

/// <summary>
/// A read-through wrapper that cancels a token once <paramref name="threshold"/> bytes have been read.
/// </summary>
/// <remarks>
/// Cancelling from inside the payload stage is the only way to test that the stage itself is
/// cancellable, rather than only its entry.
/// </remarks>
/// <param name="inner">The stream to read from.</param>
/// <param name="threshold">How many bytes to allow through before cancelling.</param>
/// <param name="cancellationTokenSource">The source to cancel.</param>
internal sealed class CancelAfterStream(
    Stream inner,
    long threshold,
    CancellationTokenSource cancellationTokenSource) : Stream
{
    private long _position;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => inner.Length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = inner.Read(buffer, offset, count);
        _position += read;
        if (_position >= threshold) cancellationTokenSource.Cancel();
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        Task.FromResult(Read(buffer, offset, count));

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
