using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption;

/// <summary>
/// The default <see cref="IEncryptedDataInspector"/>, parsing a container header without any
/// credential and without reading a payload byte.
/// </summary>
/// <remarks>
/// It has no dependencies: reading a header needs no cryptographic primitive, only the format rules.
/// Stateless and safe for concurrent use; registered as a singleton by
/// <see cref="Microsoft.Extensions.DependencyInjection.ServiceCollectionExtensions.AddEnigmaDataEncryption"/>.
/// </remarks>
public sealed class EncryptedDataInspector : IEncryptedDataInspector
{
    /// <inheritdoc />
    public Task<EncryptedDataHeader> ReadHeaderAsync(
        Stream input,
        DataEncryptionLimits? limits = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        return ReadHeaderCoreAsync(input, limits ?? DataEncryptionLimits.Default, cancellationToken);
    }

    /// <summary>
    /// Parses the header through <see cref="HeaderReader"/> with <b>no expected method</b> — the
    /// inspector reads all four — and restores the stream position when it can.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The position is captured <b>before</b> the parse and restored in a <c>finally</c>, so a container
    /// this library cannot read leaves a seekable stream exactly where it was found. That matters more
    /// than the success case: a caller probing a file it is unsure about should not have its stream
    /// consumed by the attempt.
    /// </para>
    /// <para>
    /// Only <see cref="Stream.CanSeek"/> is honoured. A non-seekable stream is left at the first payload
    /// byte and the header cannot be re-read — the behaviour
    /// <see cref="IEncryptedDataInspector.ReadHeaderAsync"/> documents.
    /// </para>
    /// </remarks>
    private static async Task<EncryptedDataHeader> ReadHeaderCoreAsync(
        Stream input,
        DataEncryptionLimits limits,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        bool restorePosition = input.CanSeek;
        long originalPosition = restorePosition ? input.Position : 0L;

        try
        {
            ParsedHeader parsed = await HeaderReader
                .ReadAsync(input, expectedMethod: null, limits, cancellationToken)
                .ConfigureAwait(false);

            // Only the public projection is returned: the salt, nonce, wrapped key, encapsulation and
            // confirmation tag stay on the internal ParsedHeader, which is what lets EncryptedDataHeader
            // carry no secret (docs/format.md §2, and the record's own remarks).
            return parsed.Header;
        }
        finally
        {
            if (restorePosition) input.Position = originalPosition;
        }
    }
}
