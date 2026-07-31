using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// An HMAC factory that keeps a reference to every key an HMAC was computed under, plus a copy taken at the
/// time.
/// </summary>
/// <remarks>
/// <para>
/// This is how the hybrid method's <b>combined</b> data key is observed at all. It is created inside
/// <c>HybridKeyCombiner</c> and never crosses a seam a test can reach — but it is then used as the HMAC key
/// of the key-confirmation derivation, so a factory that records its keys by reference ends up holding the
/// very array the service is responsible for clearing.
/// </para>
/// <para>
/// Four keys pass through one hybrid call, and all four are key material that must be gone by the time it
/// returns: the RSA-half secret and the ML-KEM shared secret (one combiner branch each), the combined data
/// key (deriving <c>kcKey</c>), and <c>kcKey</c> itself (tagging the header). Asserting "every key this
/// factory saw is now zero" therefore covers the whole set in one statement, without needing a seam per
/// buffer.
/// </para>
/// </remarks>
internal sealed class HmacKeyRecordingFactory : IHmacServiceFactory
{
    /// <summary>Every key an HMAC was computed under, by reference.</summary>
    internal List<byte[]> Keys { get; } = [];

    /// <summary>Copies of those keys, taken as they were used.</summary>
    internal List<byte[]> Snapshots { get; } = [];

    /// <inheritdoc />
    public IHmacService CreateHmacSha1Service(int bufferSize = 4096) =>
        Wrap(new HmacServiceFactory().CreateHmacSha1Service(bufferSize));

    /// <inheritdoc />
    public IHmacService CreateHmacSha256Service(int bufferSize = 4096) =>
        Wrap(new HmacServiceFactory().CreateHmacSha256Service(bufferSize));

    /// <inheritdoc />
    public IHmacService CreateHmacSha512Service(int bufferSize = 4096) =>
        Wrap(new HmacServiceFactory().CreateHmacSha512Service(bufferSize));

    private IHmacService Wrap(IHmacService inner) => new RecordingHmacService(inner, this);

    private sealed class RecordingHmacService(IHmacService inner, HmacKeyRecordingFactory recorder)
        : IHmacService
    {
        public byte[] ComputeHmac(byte[] data, byte[] key)
        {
            recorder.Keys.Add(key);
            recorder.Snapshots.Add((byte[])key.Clone());
            return inner.ComputeHmac(data, key);
        }

        public Task<byte[]> ComputeHmacAsync(
            Stream data,
            byte[] key,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default)
        {
            recorder.Keys.Add(key);
            recorder.Snapshots.Add((byte[])key.Clone());
            return inner.ComputeHmacAsync(data, key, progress, cancellationToken);
        }
    }
}
