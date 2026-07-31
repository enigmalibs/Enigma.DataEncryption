using System;
using System.Collections.Generic;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>A deterministic <see cref="IRandomSource"/> for the RSA method, keyed on the size requested.</summary>
/// <remarks>
/// The two draws an RSA encrypt makes are distinguishable by length alone — 32 bytes of data key and 12 of
/// nonce — so the source does not need to know the call order, which keeps it from silently "passing" if
/// the implementation ever asks for them the other way round.
/// </remarks>
/// <param name="dataKey">The 32 bytes to answer a data-key-sized request with.</param>
/// <param name="nonce">The 12 bytes to answer a nonce-sized request with.</param>
internal sealed class FixedDataKeyAndNonceSource(byte[] dataKey, byte[] nonce) : IRandomSource
{
    /// <summary>How many times each size was requested.</summary>
    internal Dictionary<int, int> Requests { get; } = [];

    /// <inheritdoc />
    public byte[] GenerateRandomBytes(int size)
    {
        Requests[size] = Requests.TryGetValue(size, out int count) ? count + 1 : 1;

        return size switch
        {
            DataEncryptionDefaults.DataKeySizeBytes => (byte[])dataKey.Clone(),
            DataEncryptionDefaults.NonceSizeBytes => (byte[])nonce.Clone(),
            _ => throw new InvalidOperationException(
                $"The service asked for {size} random bytes; this source only answers data-key ({DataEncryptionDefaults.DataKeySizeBytes}) and nonce ({DataEncryptionDefaults.NonceSizeBytes}) requests."),
        };
    }
}

/// <summary>
/// A real random source that keeps a reference to every buffer it hands out, so a test can check what the
/// library did with it.
/// </summary>
/// <remarks>
/// The buffers are handed out <b>by reference</b>, not cloned: that is the point. The data key the service
/// clears in its <c>finally</c> is this array, so a missed <c>finally</c> shows up here as a buffer that
/// still holds key material.
/// </remarks>
internal sealed class RecordingRandomSource : IRandomSource
{
    private readonly RandomSource _inner = new();

    /// <summary>Every buffer handed out, by reference.</summary>
    internal List<byte[]> Issued { get; } = [];

    /// <summary>Copies of those buffers, taken as they were handed out.</summary>
    internal List<byte[]> Snapshots { get; } = [];

    /// <summary>The buffers of data-key size — the ones that must end up zeroed.</summary>
    internal IEnumerable<byte[]> IssuedDataKeys
    {
        get
        {
            foreach (byte[] buffer in Issued)
            {
                if (buffer.Length == DataEncryptionDefaults.DataKeySizeBytes) yield return buffer;
            }
        }
    }

    /// <inheritdoc />
    public byte[] GenerateRandomBytes(int size)
    {
        byte[] buffer = _inner.GenerateRandomBytes(size);
        Issued.Add(buffer);
        Snapshots.Add((byte[])buffer.Clone());
        return buffer;
    }
}

/// <summary>
/// A pass-through RSA factory that records every data key an unwrap handed back, by reference.
/// </summary>
/// <remarks>
/// On the decrypt side the data key is allocated inside Enigma.Core, so this decorator is the only way to
/// get hold of the very array the service is responsible for clearing.
/// </remarks>
internal sealed class RecordingPublicKeyServiceFactory : IPublicKeyServiceFactory
{
    /// <summary>Every unwrapped data key, by reference.</summary>
    internal List<byte[]> UnwrappedKeys { get; } = [];

    /// <summary>Copies of those keys, taken at unwrap time.</summary>
    internal List<byte[]> Snapshots { get; } = [];

    /// <inheritdoc />
    public IPublicKeyService CreatePublicKeyService() => new RecordingPublicKeyService(this);

    private sealed class RecordingPublicKeyService(RecordingPublicKeyServiceFactory recorder) : IPublicKeyService
    {
        private readonly IPublicKeyService _inner = new PublicKeyServiceFactory().CreatePublicKeyService();

        public (string publicKeyPem, string privateKeyPem) GenerateRsaKeyPair(
            int keySizeBits = 2048,
            char[]? password = null) =>
            _inner.GenerateRsaKeyPair(keySizeBits, password);

        public byte[] EncryptPkcs1(byte[] data, string publicKeyPem) => _inner.EncryptPkcs1(data, publicKeyPem);

        public byte[] DecryptPkcs1(byte[] ciphertext, string privateKeyPem, char[]? password = null) =>
            _inner.DecryptPkcs1(ciphertext, privateKeyPem, password);

        public byte[] EncryptOaep(byte[] data, string publicKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256) =>
            _inner.EncryptOaep(data, publicKeyPem, hash);

        public byte[] DecryptOaep(
            byte[] ciphertext,
            string privateKeyPem,
            RsaOaepHash hash = RsaOaepHash.Sha256,
            char[]? password = null)
        {
            byte[] dataKey = _inner.DecryptOaep(ciphertext, privateKeyPem, hash, password);
            recorder.UnwrappedKeys.Add(dataKey);
            recorder.Snapshots.Add((byte[])dataKey.Clone());
            return dataKey;
        }

        public byte[] Sign(
            byte[] data,
            string privateKeyPem,
            RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa,
            char[]? password = null) =>
            _inner.Sign(data, privateKeyPem, algorithm, password);

        public bool Verify(
            byte[] data,
            byte[] signature,
            string publicKeyPem,
            RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa) =>
            _inner.Verify(data, signature, publicKeyPem, algorithm);
    }
}

/// <summary>
/// Thrown by <see cref="PoisonedPublicKeyServiceFactory"/> when an RSA operation is attempted that should
/// not have been reached.
/// </summary>
/// <param name="message">What was attempted that should not have been.</param>
internal sealed class RsaInvokedException(string message) : Exception(message);

/// <summary>An RSA factory whose service refuses to perform any key operation.</summary>
/// <remarks>
/// The RSA analogue of PHASE02's poisoned key-derivation factories. It proves ordering rather than
/// behaviour: a header whose wrapped-key length is out of bounds, an argument that is invalid, or a token
/// that is already cancelled must all be rejected <b>before</b> the private key is touched, so a call
/// driven through this factory must fail with the documented exception and never with
/// <see cref="RsaInvokedException"/>.
/// </remarks>
internal sealed class PoisonedPublicKeyServiceFactory : IPublicKeyServiceFactory
{
    /// <inheritdoc />
    public IPublicKeyService CreatePublicKeyService() => new PoisonedPublicKeyService();

    private sealed class PoisonedPublicKeyService : IPublicKeyService
    {
        public (string publicKeyPem, string privateKeyPem) GenerateRsaKeyPair(
            int keySizeBits = 2048,
            char[]? password = null) =>
            throw new RsaInvokedException($"A {keySizeBits}-bit key pair was generated; nothing should have been.");

        public byte[] EncryptPkcs1(byte[] data, string publicKeyPem) =>
            throw new RsaInvokedException("PKCS#1 encryption was attempted; this method does not use it.");

        public byte[] DecryptPkcs1(byte[] ciphertext, string privateKeyPem, char[]? password = null) =>
            throw new RsaInvokedException("PKCS#1 decryption was attempted; this method does not use it.");

        public byte[] EncryptOaep(byte[] data, string publicKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256) =>
            throw new RsaInvokedException(
                $"A {data.Length}-byte OAEP wrap was attempted; the call should have been rejected first.");

        public byte[] DecryptOaep(
            byte[] ciphertext,
            string privateKeyPem,
            RsaOaepHash hash = RsaOaepHash.Sha256,
            char[]? password = null) =>
            throw new RsaInvokedException(
                $"A {ciphertext.Length}-byte OAEP unwrap was attempted; the header should have been rejected first.");

        public byte[] Sign(
            byte[] data,
            string privateKeyPem,
            RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa,
            char[]? password = null) =>
            throw new RsaInvokedException("A signature was produced; this method never signs.");

        public bool Verify(
            byte[] data,
            byte[] signature,
            string publicKeyPem,
            RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa) =>
            throw new RsaInvokedException("A signature was verified; this method never verifies.");
    }
}
