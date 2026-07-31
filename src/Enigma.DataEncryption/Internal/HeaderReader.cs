using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Extensions;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Parses a container header from a forward-only stream, recovering both the header's fields and the
/// exact bytes it consumed.
/// </summary>
/// <remarks>
/// <para>
/// <b>The associated data is tee-ed, not re-serialized.</b> Every byte the parse consumes is mirrored
/// into a <see cref="MemoryStream"/> as it is read, so the AAD handed to the GCM operation is
/// definitionally what was on the wire. Rebuilding it from the parsed fields is the obvious approach
/// and it is a trap: any asymmetry between <see cref="HeaderWriter"/> and this reader would then
/// produce a mismatching AAD and surface as a confusing authentication failure at the end of the
/// payload rather than as the parse error it really is.
/// </para>
/// <para>
/// <b>Enigma.Core's stream failures are translated here and go no further.</b>
/// <c>ReadBytesAsync</c> / <c>ReadIntAsync</c> throw <see cref="IOException"/> when the stream ends
/// early, and <c>ReadLengthValueAsync</c> throws <see cref="InvalidOperationException"/> when a length
/// is out of range. Both mean the same thing to a caller — this is not a header I can parse — so both
/// become <see cref="DataEncryptionFormatException"/> at this boundary
/// (<c>docs/format.md</c> §9).
/// </para>
/// <para>
/// The stream need not be seekable and is never disposed. On return it is positioned at the first
/// payload byte.
/// </para>
/// </remarks>
internal static class HeaderReader
{
    /// <summary>
    /// Reads and validates the header at the current position of <paramref name="input"/>.
    /// </summary>
    /// <param name="input">The container stream, positioned at the magic.</param>
    /// <param name="expectedMethod">
    /// The method the calling service implements, so that handing it another method's container is a
    /// format error rather than a silent misparse. Pass <see langword="null"/> to accept any method —
    /// what the inspector does.
    /// </param>
    /// <param name="limits">The bounds to apply to every cost and length field.</param>
    /// <param name="cancellationToken">Token to cancel the read.</param>
    /// <returns>The parsed fields, the raw header bytes, and the method-specific key material.</returns>
    /// <exception cref="DataEncryptionFormatException">
    /// The magic, method, version, cipher, OAEP-hash or parameter-set byte is invalid; the stream ends
    /// inside the header; or a cost or length field is out of bounds.
    /// </exception>
    internal static async Task<ParsedHeader> ReadAsync(
        Stream input,
        EncryptionMethod? expectedMethod,
        DataEncryptionLimits limits,
        CancellationToken cancellationToken)
    {
        using MemoryStream mirror = new(FormatLayout.Argon2HeaderLength);
        TeeStream tee = new(input, mirror);

        try
        {
            byte[] magic = await tee.ReadBytesAsync(FormatLayout.MagicLength, cancellationToken)
                .ConfigureAwait(false);
            if (magic[0] != FormatLayout.MagicByte0 || magic[1] != FormatLayout.MagicByte1)
            {
                throw new DataEncryptionFormatException(
                    $"Not an Enigma.DataEncryption container: expected magic EC DE, found {magic[0]:X2} {magic[1]:X2}.");
            }

            EncryptionMethod method = MethodFromHeaderByte(
                await tee.ReadByteAsync(cancellationToken).ConfigureAwait(false));
            if (expectedMethod.HasValue && method != expectedMethod.Value)
            {
                throw new DataEncryptionFormatException(
                    $"Container was produced by the {method} method (byte 0x{(byte)method:X2}); this service reads {expectedMethod.Value} (byte 0x{(byte)expectedMethod.Value:X2}) only.");
            }

            byte version = await tee.ReadByteAsync(cancellationToken).ConfigureAwait(false);
            if (version != DataEncryptionDefaults.FormatVersion)
            {
                throw new DataEncryptionFormatException(
                    $"Unsupported container format version 0x{version:X2}; this library reads 0x{DataEncryptionDefaults.FormatVersion:X2} only.");
            }

            Cipher cipher = CipherResolver.FromHeaderByte(
                await tee.ReadByteAsync(cancellationToken).ConfigureAwait(false));

            return method switch
            {
                EncryptionMethod.Pbkdf2 =>
                    await ReadPbkdf2BodyAsync(tee, mirror, cipher, limits, cancellationToken).ConfigureAwait(false),
                EncryptionMethod.Argon2 =>
                    await ReadArgon2BodyAsync(tee, mirror, cipher, limits, cancellationToken).ConfigureAwait(false),
                EncryptionMethod.Rsa =>
                    await ReadRsaBodyAsync(tee, mirror, cipher, limits, cancellationToken).ConfigureAwait(false),
                EncryptionMethod.MLKem =>
                    await ReadMLKemBodyAsync(tee, mirror, cipher, limits, cancellationToken).ConfigureAwait(false),
                EncryptionMethod.Hybrid =>
                    await ReadHybridBodyAsync(tee, mirror, cipher, limits, cancellationToken).ConfigureAwait(false),
                // Unreachable: MethodFromHeaderByte admits no other value. Kept so that adding a
                // method to the enum without a body reader is a clean failure rather than a misparse.
                _ => throw new DataEncryptionFormatException(
                    $"Undefined container method byte 0x{(byte)method:X2} at header offset 2."),
            };
        }
        catch (IOException exception)
        {
            throw new DataEncryptionFormatException(
                "The stream ended inside the container header.", exception);
        }
        catch (InvalidOperationException exception)
        {
            throw new DataEncryptionFormatException(
                "A container header length field is negative or above its permitted maximum.", exception);
        }
    }

    private static async Task<ParsedHeader> ReadPbkdf2BodyAsync(
        Stream tee,
        MemoryStream mirror,
        Cipher cipher,
        DataEncryptionLimits limits,
        CancellationToken cancellationToken)
    {
        byte[] nonce = await tee.ReadBytesAsync(DataEncryptionDefaults.NonceSizeBytes, cancellationToken)
            .ConfigureAwait(false);
        byte[] salt = await tee.ReadBytesAsync(DataEncryptionDefaults.SaltSizeBytes, cancellationToken)
            .ConfigureAwait(false);
        int iterations = await tee.ReadIntAsync(cancellationToken).ConfigureAwait(false);

        LimitsValidator.ValidatePbkdf2Iterations(iterations, limits);

        byte[] tag = await ReadKeyConfirmationTagAsync(tee, cancellationToken).ConfigureAwait(false);

        return new ParsedHeader
        {
            Header = new EncryptedDataHeader
            {
                Method = EncryptionMethod.Pbkdf2,
                FormatVersion = DataEncryptionDefaults.FormatVersion,
                Cipher = cipher,
                HeaderLength = FormatLayout.Pbkdf2HeaderLength,
                Pbkdf2Iterations = iterations,
            },
            HeaderBytes = mirror.ToArray(),
            Nonce = nonce,
            Salt = salt,
            KeyConfirmationTag = tag,
        };
    }

    private static async Task<ParsedHeader> ReadArgon2BodyAsync(
        Stream tee,
        MemoryStream mirror,
        Cipher cipher,
        DataEncryptionLimits limits,
        CancellationToken cancellationToken)
    {
        byte[] nonce = await tee.ReadBytesAsync(DataEncryptionDefaults.NonceSizeBytes, cancellationToken)
            .ConfigureAwait(false);
        byte[] salt = await tee.ReadBytesAsync(DataEncryptionDefaults.SaltSizeBytes, cancellationToken)
            .ConfigureAwait(false);
        int iterations = await tee.ReadIntAsync(cancellationToken).ConfigureAwait(false);
        int degreeOfParallelism = await tee.ReadIntAsync(cancellationToken).ConfigureAwait(false);
        int memorySizeKb = await tee.ReadIntAsync(cancellationToken).ConfigureAwait(false);

        LimitsValidator.ValidateArgon2(iterations, degreeOfParallelism, memorySizeKb, limits);

        byte[] tag = await ReadKeyConfirmationTagAsync(tee, cancellationToken).ConfigureAwait(false);

        return new ParsedHeader
        {
            Header = new EncryptedDataHeader
            {
                Method = EncryptionMethod.Argon2,
                FormatVersion = DataEncryptionDefaults.FormatVersion,
                Cipher = cipher,
                HeaderLength = FormatLayout.Argon2HeaderLength,
                Argon2Iterations = iterations,
                Argon2DegreeOfParallelism = degreeOfParallelism,
                Argon2MemorySizeKb = memorySizeKb,
            },
            HeaderBytes = mirror.ToArray(),
            Nonce = nonce,
            Salt = salt,
            KeyConfirmationTag = tag,
        };
    }

    /// <summary>
    /// Reads a method-<c>0x03</c> body: OAEP hash, nonce, then the wrapped key as a length-value field.
    /// </summary>
    /// <remarks>
    /// The OAEP-hash byte precedes the nonce, exactly where ML-KEM puts its parameter set
    /// (<c>docs/format.md</c> §3.3). It is the header — never the caller — that selects the unwrap, so an
    /// edited byte does not fail here: it names a hash the wrap did not use, and OAEP reports that.
    /// </remarks>
    private static async Task<ParsedHeader> ReadRsaBodyAsync(
        Stream tee,
        MemoryStream mirror,
        Cipher cipher,
        DataEncryptionLimits limits,
        CancellationToken cancellationToken)
    {
        RsaOaepHash oaepHash = RsaOaepHashWire.FromWireByte(
            await tee.ReadByteAsync(cancellationToken).ConfigureAwait(false));

        byte[] nonce = await tee.ReadBytesAsync(DataEncryptionDefaults.NonceSizeBytes, cancellationToken)
            .ConfigureAwait(false);

        // Enigma.Core's own cap is the first line of defence, so a hostile length never reaches an
        // allocation; its InvalidOperationException is translated by the caller. The explicit check
        // that follows names the field and rejects zero, which Enigma.Core would allow.
        byte[] wrappedKey = await tee.ReadLengthValueAsync(limits.MaxWrappedKeyLength, cancellationToken)
            .ConfigureAwait(false);
        LimitsValidator.ValidateWrappedKeyLength(wrappedKey.Length, limits);

        byte[] tag = await ReadKeyConfirmationTagAsync(tee, cancellationToken).ConfigureAwait(false);

        return new ParsedHeader
        {
            Header = new EncryptedDataHeader
            {
                Method = EncryptionMethod.Rsa,
                FormatVersion = DataEncryptionDefaults.FormatVersion,
                Cipher = cipher,
                HeaderLength = FormatLayout.RsaHeaderBaseLength + wrappedKey.Length,
                RsaOaepHash = oaepHash,
                WrappedKeyLength = wrappedKey.Length,
            },
            HeaderBytes = mirror.ToArray(),
            Nonce = nonce,
            WrappedKey = wrappedKey,
            RsaOaepHash = oaepHash,
            KeyConfirmationTag = tag,
        };
    }

    private static async Task<ParsedHeader> ReadMLKemBodyAsync(
        Stream tee,
        MemoryStream mirror,
        Cipher cipher,
        DataEncryptionLimits limits,
        CancellationToken cancellationToken)
    {
        // The parameter-set byte precedes the nonce for ML-KEM — docs/format.md §3.4.
        MLKemParameterSet parameterSet = MLKemParameterSetWire.FromWireByte(
            await tee.ReadByteAsync(cancellationToken).ConfigureAwait(false));

        byte[] nonce = await tee.ReadBytesAsync(DataEncryptionDefaults.NonceSizeBytes, cancellationToken)
            .ConfigureAwait(false);

        byte[] encapsulation = await tee.ReadLengthValueAsync(limits.MaxEncapsulationLength, cancellationToken)
            .ConfigureAwait(false);
        LimitsValidator.ValidateEncapsulationLength(encapsulation.Length, limits);

        byte[] tag = await ReadKeyConfirmationTagAsync(tee, cancellationToken).ConfigureAwait(false);

        return new ParsedHeader
        {
            Header = new EncryptedDataHeader
            {
                Method = EncryptionMethod.MLKem,
                FormatVersion = DataEncryptionDefaults.FormatVersion,
                Cipher = cipher,
                HeaderLength = FormatLayout.MLKemHeaderBaseLength + encapsulation.Length,
                MLKemParameterSet = parameterSet,
                EncapsulationLength = encapsulation.Length,
            },
            HeaderBytes = mirror.ToArray(),
            Nonce = nonce,
            Encapsulation = encapsulation,
            MLKemParameterSet = parameterSet,
            KeyConfirmationTag = tag,
        };
    }

    /// <summary>
    /// Reads a method-<c>0x05</c> body: parameter set, nonce, then <b>two</b> length-value fields.
    /// </summary>
    /// <remarks>
    /// The order is the wrapped RSA secret first, the encapsulation second — the order of
    /// <c>docs/format.md</c> §3.5, and the order the key combiner's transcript assumes (§3.5.1). Both
    /// lengths are bounded before their buffers are allocated, and by the same two caps methods
    /// <c>0x03</c> and <c>0x04</c> use: they are the same two quantities, so §8 gives the hybrid no caps
    /// of its own.
    /// </remarks>
    private static async Task<ParsedHeader> ReadHybridBodyAsync(
        Stream tee,
        MemoryStream mirror,
        Cipher cipher,
        DataEncryptionLimits limits,
        CancellationToken cancellationToken)
    {
        // As for ML-KEM, the parameter-set byte precedes the nonce — docs/format.md §3.5.
        MLKemParameterSet parameterSet = MLKemParameterSetWire.FromWireByte(
            await tee.ReadByteAsync(cancellationToken).ConfigureAwait(false));

        byte[] nonce = await tee.ReadBytesAsync(DataEncryptionDefaults.NonceSizeBytes, cancellationToken)
            .ConfigureAwait(false);

        byte[] wrappedSecret = await tee.ReadLengthValueAsync(limits.MaxWrappedKeyLength, cancellationToken)
            .ConfigureAwait(false);
        LimitsValidator.ValidateWrappedKeyLength(wrappedSecret.Length, limits);

        byte[] encapsulation = await tee.ReadLengthValueAsync(limits.MaxEncapsulationLength, cancellationToken)
            .ConfigureAwait(false);
        LimitsValidator.ValidateEncapsulationLength(encapsulation.Length, limits);

        byte[] tag = await ReadKeyConfirmationTagAsync(tee, cancellationToken).ConfigureAwait(false);

        return new ParsedHeader
        {
            Header = new EncryptedDataHeader
            {
                Method = EncryptionMethod.Hybrid,
                FormatVersion = DataEncryptionDefaults.FormatVersion,
                Cipher = cipher,
                HeaderLength =
                    FormatLayout.HybridHeaderBaseLength + wrappedSecret.Length + encapsulation.Length,
                MLKemParameterSet = parameterSet,
                WrappedKeyLength = wrappedSecret.Length,
                EncapsulationLength = encapsulation.Length,
            },
            HeaderBytes = mirror.ToArray(),
            Nonce = nonce,
            WrappedKey = wrappedSecret,
            Encapsulation = encapsulation,
            MLKemParameterSet = parameterSet,
            KeyConfirmationTag = tag,
        };
    }

    private static Task<byte[]> ReadKeyConfirmationTagAsync(Stream tee, CancellationToken cancellationToken) =>
        tee.ReadBytesAsync(DataEncryptionDefaults.KeyConfirmationTagSizeBytes, cancellationToken);

    private static EncryptionMethod MethodFromHeaderByte(byte value) => value switch
    {
        (byte)EncryptionMethod.Pbkdf2 => EncryptionMethod.Pbkdf2,
        (byte)EncryptionMethod.Argon2 => EncryptionMethod.Argon2,
        (byte)EncryptionMethod.Rsa => EncryptionMethod.Rsa,
        (byte)EncryptionMethod.MLKem => EncryptionMethod.MLKem,
        (byte)EncryptionMethod.Hybrid => EncryptionMethod.Hybrid,
        _ => throw new DataEncryptionFormatException(
            $"Undefined container method byte 0x{value:X2} at header offset 2."),
    };

    /// <summary>
    /// A forward-only read-through wrapper that mirrors every byte it yields into a
    /// <see cref="MemoryStream"/>.
    /// </summary>
    /// <remarks>
    /// Wrapping the stream — rather than tee-ing at each call site — is what makes the mirror complete:
    /// <c>ReadLengthValueAsync</c> consumes its 4-byte length prefix inside Enigma.Core, where a
    /// call-site tee cannot see it. It reports itself as non-seekable and non-writable so nothing
    /// upstream can move the position behind the mirror's back, and it never disposes the stream it
    /// wraps.
    /// </remarks>
    private sealed class TeeStream : Stream
    {
        private readonly Stream _inner;
        private readonly MemoryStream _mirror;

        internal TeeStream(Stream inner, MemoryStream mirror)
        {
            _inner = inner;
            _mirror = mirror;
        }

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
            int read = _inner.Read(buffer, offset, count);
            if (read > 0) _mirror.Write(buffer, offset, read);
            return read;
        }

        public override async Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            int read = await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            if (read > 0) _mirror.Write(buffer, offset, read);
            return read;
        }

#if !NETSTANDARD2_0
        public override int Read(Span<byte> buffer)
        {
            int read = _inner.Read(buffer);
            if (read > 0) _mirror.Write(buffer.Slice(0, read));
            return read;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            int read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read > 0) _mirror.Write(buffer.Span.Slice(0, read));
            return read;
        }
#endif

        public override void Flush()
        {
            // Nothing is buffered on the write side: this stream is read-only.
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
