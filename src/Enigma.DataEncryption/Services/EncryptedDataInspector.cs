using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

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
        CancellationToken cancellationToken = default) =>
        throw new NotImplementedException();
}
