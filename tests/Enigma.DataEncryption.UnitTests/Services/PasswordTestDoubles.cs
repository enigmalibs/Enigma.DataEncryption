using System;
using System.Collections.Generic;
using System.Threading;
using Enigma.Core.KeyDerivation;
using Enigma.DataEncryption.Internal;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>A deterministic <see cref="IRandomSource"/>, keyed on the size requested.</summary>
/// <remarks>
/// The two calls a password-based encrypt makes are distinguishable by length alone — 16 bytes of salt
/// and 12 of nonce — so the source does not need to know the call order, which keeps it from silently
/// "passing" if the implementation ever asks for them the other way round.
/// </remarks>
/// <param name="salt">The 16 bytes to answer a salt-sized request with.</param>
/// <param name="nonce">The 12 bytes to answer a nonce-sized request with.</param>
internal sealed class FixedRandomSource(byte[] salt, byte[] nonce) : IRandomSource
{
    /// <summary>How many times each size was requested.</summary>
    internal Dictionary<int, int> Requests { get; } = [];

    /// <inheritdoc />
    public byte[] GenerateRandomBytes(int size)
    {
        Requests[size] = Requests.TryGetValue(size, out int count) ? count + 1 : 1;

        return size switch
        {
            DataEncryptionDefaults.SaltSizeBytes => (byte[])salt.Clone(),
            DataEncryptionDefaults.NonceSizeBytes => (byte[])nonce.Clone(),
            _ => throw new InvalidOperationException(
                $"The service asked for {size} random bytes; this source only answers salt ({DataEncryptionDefaults.SaltSizeBytes}) and nonce ({DataEncryptionDefaults.NonceSizeBytes}) requests."),
        };
    }
}

/// <summary>
/// Thrown by the poisoned key-derivation factories when a derivation is attempted that should not have
/// been reached.
/// </summary>
/// <param name="message">What was derived that should not have been.</param>
internal sealed class KdfInvokedException(string message) : Exception(message);

/// <summary>A PBKDF2 factory whose service refuses to derive anything.</summary>
/// <remarks>
/// Used to prove the ordering promised by <c>docs/format.md</c> §7.2 step 3: a header whose cost field
/// is out of bounds is rejected <b>before</b> any derivation, so a decrypt driven through this factory
/// must still fail with <see cref="DataEncryptionFormatException"/> and never with
/// <see cref="KdfInvokedException"/>.
/// </remarks>
internal sealed class PoisonedPbkdf2ServiceFactory : IPbkdf2ServiceFactory
{
    /// <inheritdoc />
    public IPbkdf2Service CreatePbkdf2Service() => new PoisonedPbkdf2Service();

    private sealed class PoisonedPbkdf2Service : IPbkdf2Service
    {
        public byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int keySizeBytes, Pbkdf2Prf prf) =>
            throw new KdfInvokedException(
                $"PBKDF2 was invoked with {iterations} iterations; the header should have been rejected first.");
    }
}

/// <summary>An Argon2 factory whose service refuses to derive anything.</summary>
/// <remarks>
/// The Argon2 case is the pointed one: a header claiming <see cref="int.MaxValue"/> KiB of memory must
/// cost nothing to reject. If this factory is ever reached, the allocation would have been attempted.
/// </remarks>
internal sealed class PoisonedArgon2ServiceFactory : IArgon2ServiceFactory
{
    /// <inheritdoc />
    public IArgon2Service CreateArgon2Service() => new PoisonedArgon2Service();

    private sealed class PoisonedArgon2Service : IArgon2Service
    {
        public byte[] DeriveKey(
            byte[] password,
            byte[] salt,
            int iterations,
            int memorySizeKb,
            int degreeOfParallelism,
            int keySizeBytes,
            Argon2Variant variant,
            Argon2Version version) =>
            throw new KdfInvokedException(
                $"Argon2 was invoked with {iterations} passes over {memorySizeKb} KiB; the header should have been rejected first.");
    }
}

/// <summary>
/// A synchronous <see cref="IProgress{T}"/> that records every value on the reporting thread.
/// </summary>
/// <remarks>
/// <see cref="Progress{T}"/> posts its callbacks through a synchronization context, so a test using it
/// would race the assertions against the last few reports. This one does not.
/// </remarks>
internal sealed class ProgressCollector : IProgress<int>
{
    private readonly List<int> _values = [];
    private readonly object _gate = new();

    /// <summary>Every value reported, in order.</summary>
    internal IReadOnlyList<int> Values
    {
        get
        {
            lock (_gate) return [.. _values];
        }
    }

    /// <summary>The sum of every reported value — the payload byte count, per the XML docs.</summary>
    internal long Total
    {
        get
        {
            lock (_gate)
            {
                long total = 0;
                foreach (int value in _values) total += value;
                return total;
            }
        }
    }

    /// <inheritdoc />
    public void Report(int value)
    {
        lock (_gate) _values.Add(value);
    }
}
