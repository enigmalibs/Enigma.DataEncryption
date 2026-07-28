using System;
using System.Collections.Generic;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// A deterministic <see cref="IRandomSource"/> that answers <b>only</b> nonce-sized requests.
/// </summary>
/// <remarks>
/// The refusal is the point. ML-KEM is the one method that generates no key material of its own — the
/// encapsulated shared secret <i>is</i> the data key (<c>docs/format.md</c> §3.4) — so an implementation
/// that drew 32 random bytes and used them would round-trip perfectly with itself while producing a
/// container no other reader could open. This source turns that mistake into a failure.
/// </remarks>
/// <param name="nonce">The 12 bytes to answer a nonce-sized request with.</param>
internal sealed class FixedNonceSource(byte[] nonce) : IRandomSource
{
    /// <summary>How many times each size was requested.</summary>
    internal Dictionary<int, int> Requests { get; } = [];

    /// <inheritdoc />
    public byte[] GenerateRandomBytes(int size)
    {
        Requests[size] = Requests.TryGetValue(size, out int count) ? count + 1 : 1;

        return size == DataEncryptionDefaults.NonceSizeBytes
            ? (byte[])nonce.Clone()
            : throw new InvalidOperationException(
                $"The service asked for {size} random bytes; the ML-KEM method must draw the {DataEncryptionDefaults.NonceSizeBytes}-byte nonce and nothing else — the data key is the encapsulated shared secret.");
    }
}

/// <summary>
/// A pass-through ML-KEM factory that records every shared secret it handed out, by reference.
/// </summary>
/// <remarks>
/// Both of the service's shared secrets are allocated inside Enigma.Core — the encapsulated one on the
/// encrypt side, the decapsulated one on the decrypt side — so this decorator is the only way to get hold of
/// the very arrays the service is responsible for clearing. Unlike the RSA equivalent, one double covers
/// both directions, because one interface produces both.
/// </remarks>
// ReSharper disable once InconsistentNaming
internal sealed class RecordingMLKemServiceFactory : IMLKemServiceFactory
{
    /// <summary>Every shared secret produced by an encapsulation, by reference.</summary>
    internal List<byte[]> EncapsulatedSecrets { get; } = [];

    /// <summary>Every shared secret produced by a decapsulation, by reference.</summary>
    internal List<byte[]> DecapsulatedSecrets { get; } = [];

    /// <summary>Copies of every secret above, taken as it was handed out.</summary>
    internal List<byte[]> Snapshots { get; } = [];

    /// <summary>The parameter sets the service asked for, in order.</summary>
    internal List<MLKemParameterSet> RequestedParameterSets { get; } = [];

    /// <inheritdoc />
    public IMLKemService CreateMLKemService(MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768)
    {
        RequestedParameterSets.Add(parameterSet);
        return new RecordingMLKemService(this, parameterSet);
    }

    private sealed class RecordingMLKemService(RecordingMLKemServiceFactory recorder, MLKemParameterSet parameterSet)
        : IMLKemService
    {
        private readonly IMLKemService _inner = new MLKemServiceFactory().CreateMLKemService(parameterSet);

        public (byte[] publicKey, byte[] privateKey) GenerateKeyPair() => _inner.GenerateKeyPair();

        public (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey)
        {
            (byte[] ciphertext, byte[] sharedSecret) = _inner.Encapsulate(publicKey);
            recorder.EncapsulatedSecrets.Add(sharedSecret);
            recorder.Snapshots.Add((byte[])sharedSecret.Clone());
            return (ciphertext, sharedSecret);
        }

        public byte[] Decapsulate(byte[] ciphertext, byte[] privateKey)
        {
            byte[] sharedSecret = _inner.Decapsulate(ciphertext, privateKey);
            recorder.DecapsulatedSecrets.Add(sharedSecret);
            recorder.Snapshots.Add((byte[])sharedSecret.Clone());
            return sharedSecret;
        }
    }
}

/// <summary>
/// Thrown by <see cref="PoisonedMLKemServiceFactory"/> when a KEM operation is attempted that should not have
/// been reached.
/// </summary>
/// <param name="message">What was attempted that should not have been.</param>
// ReSharper disable once InconsistentNaming
internal sealed class MLKemInvokedException(string message) : Exception(message);

/// <summary>An ML-KEM factory whose service refuses to perform any key operation.</summary>
/// <remarks>
/// The ML-KEM analogue of PHASE02's poisoned key-derivation factories and PHASE03's poisoned RSA factory. It
/// proves ordering rather than behaviour: a header whose encapsulation length is out of bounds, an argument
/// that is invalid, or a token that is already cancelled must all be rejected <b>before</b> the private key
/// is touched, so a call driven through this factory must fail with the documented exception and never with
/// <see cref="MLKemInvokedException"/>.
/// </remarks>
// ReSharper disable once InconsistentNaming
internal sealed class PoisonedMLKemServiceFactory : IMLKemServiceFactory
{
    /// <inheritdoc />
    public IMLKemService CreateMLKemService(MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768) =>
        new PoisonedMLKemService();

    private sealed class PoisonedMLKemService : IMLKemService
    {
        public (byte[] publicKey, byte[] privateKey) GenerateKeyPair() =>
            throw new MLKemInvokedException("A key pair was generated; nothing should have been.");

        public (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey) =>
            throw new MLKemInvokedException(
                $"An encapsulation against a {publicKey.Length}-byte public key was attempted; the call should have been rejected first.");

        public byte[] Decapsulate(byte[] ciphertext, byte[] privateKey) =>
            throw new MLKemInvokedException(
                $"A decapsulation of {ciphertext.Length} bytes was attempted; the header should have been rejected first.");
    }
}
