using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Proves the key-clearing contract instead of asserting it in a comment: the derived data key, the
/// key-confirmation key and the temporary UTF-8 password buffer are all zeroed by the time a call
/// returns — and are zeroed even when the call fails part-way.
/// </summary>
/// <remarks>
/// <para>
/// The predecessor library's code review raised exactly this as its one High-severity finding, caused by
/// clearing outside <c>try/finally</c>. The recording spies below hold the very arrays the production
/// code was handed or handed back, so a missed <c>finally</c> shows up here as a buffer that still holds
/// key material.
/// </para>
/// <para>
/// The caller's own password array is the exception: it must survive untouched, which
/// <c>PasswordRoundTripTests</c> asserts and which the <c>byte[]</c> case below re-checks from the other
/// side.
/// </para>
/// </remarks>
public sealed class KeyMaterialClearingTests
{
    /// <summary>Both methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<PasswordMethod> Methods() => [PasswordMethod.Pbkdf2, PasswordMethod.Argon2];

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EncryptClearsTheDerivedDataKey(PasswordMethod method)
    {
        RecordingKdf kdf = new();
        using MemoryStream input = new(PasswordTestData.Plaintext(128), writable: false);
        using MemoryStream output = new();

        await Recorded(method, kdf, out RecordingHmacServiceFactory hmac).EncryptAsync(
            input, output, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        AssertDerivedKeyWasUsedThenCleared(kdf);
        AssertEveryHmacKeyWasCleared(hmac);
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task DecryptClearsTheDerivedDataKey(PasswordMethod method)
    {
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            PasswordServiceAdapter.Create(method), PasswordTestData.Plaintext(128));

        RecordingKdf kdf = new();
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Recorded(method, kdf, out RecordingHmacServiceFactory hmac).DecryptAsync(
            input, output, PasswordTestData.PasswordBytes(), null, null, TestContext.Current.CancellationToken);

        AssertDerivedKeyWasUsedThenCleared(kdf);
        AssertEveryHmacKeyWasCleared(hmac);
    }

    /// <summary>
    /// The <c>finally</c> has to enclose the failure paths too — a wrong password must not leave the
    /// derived key behind.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AFailedDecryptStillClearsTheDerivedDataKey(PasswordMethod method)
    {
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            PasswordServiceAdapter.Create(method), PasswordTestData.Plaintext(128));

        RecordingKdf kdf = new();
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => Recorded(method, kdf, out _).DecryptAsync(
                input, output, PasswordTestData.WrongPasswordBytes(), null, null, TestContext.Current.CancellationToken));

        AssertDerivedKeyWasUsedThenCleared(kdf);
    }

    /// <summary>And a payload that fails authentication, which fails later still.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ATamperedPayloadStillClearsTheDerivedDataKey(PasswordMethod method)
    {
        PasswordServiceAdapter writer = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(writer, PasswordTestData.Plaintext(128));
        container[^1] ^= 0x01;

        RecordingKdf kdf = new();
        using MemoryStream input = new(container, writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => Recorded(method, kdf, out _).DecryptAsync(
                input, output, PasswordTestData.PasswordBytes(), null, null, TestContext.Current.CancellationToken));

        AssertDerivedKeyWasUsedThenCleared(kdf);
    }

    /// <summary>
    /// The <c>char[]</c> overload's temporary UTF-8 buffer is the library's to clear — and the buffer the
    /// key-derivation service is handed <i>is</i> that temporary, so the spy sees it zeroed afterwards.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheCharOverloadClearsItsTemporaryPasswordBuffer(PasswordMethod method)
    {
        RecordingKdf kdf = new();
        using MemoryStream input = new(PasswordTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Recorded(method, kdf, out _).EncryptAsync(
            input, output, Cipher.Aes256Gcm, PasswordTestData.PasswordChars(), null, TestContext.Current.CancellationToken);

        Assert.NotEmpty(kdf.Passwords);
        foreach (byte[] password in kdf.Passwords)
        {
            Assert.All(password, value => Assert.Equal(0, value));
        }
    }

    /// <summary>
    /// The <c>byte[]</c> overload's password is the caller's array, so it must be left exactly as it was —
    /// the same spy, the opposite expectation.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheByteOverloadLeavesTheCallersPasswordAlone(PasswordMethod method)
    {
        RecordingKdf kdf = new();
        using MemoryStream input = new(PasswordTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Recorded(method, kdf, out _).EncryptAsync(
            input, output, Cipher.Aes256Gcm, PasswordTestData.PasswordBytes(), null, TestContext.Current.CancellationToken);

        Assert.NotEmpty(kdf.Passwords);
        foreach (byte[] password in kdf.Passwords)
        {
            Assert.Equal(PasswordTestData.PasswordBytes(), password);
        }
    }

    private static void AssertDerivedKeyWasUsedThenCleared(RecordingKdf kdf)
    {
        Assert.NotEmpty(kdf.DerivedKeys);

        for (int i = 0; i < kdf.DerivedKeys.Count; i++)
        {
            // The snapshot proves the test is not passing on a key that was zero to begin with.
            Assert.Contains((byte)0x01, Nonzero(kdf.Snapshots[i]));
            Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, kdf.DerivedKeys[i].Length);
            Assert.All(kdf.DerivedKeys[i], value => Assert.Equal(0, value));
        }
    }

    private static void AssertEveryHmacKeyWasCleared(RecordingHmacServiceFactory hmac)
    {
        // Two HMAC keys pass through a call: the data key (deriving kcKey) and kcKey itself (tagging the
        // header). Both are key material and both must be gone.
        Assert.NotEmpty(hmac.Keys);
        foreach (byte[] key in hmac.Keys)
        {
            Assert.All(key, value => Assert.Equal(0, value));
        }
    }

    /// <summary>Maps a buffer to a marker per non-zero byte, so "was it ever non-zero" is assertable.</summary>
    private static byte[] Nonzero(byte[] buffer)
    {
        byte[] markers = new byte[buffer.Length];
        for (int i = 0; i < buffer.Length; i++)
        {
            markers[i] = buffer[i] == 0 ? (byte)0x00 : (byte)0x01;
        }

        return markers;
    }

    private static PasswordServiceAdapter Recorded(
        PasswordMethod method,
        RecordingKdf kdf,
        out RecordingHmacServiceFactory hmacFactory)
    {
        hmacFactory = new RecordingHmacServiceFactory();

        return method == PasswordMethod.Pbkdf2
            ? new RecordingPbkdf2Adapter(kdf, hmacFactory)
            : new RecordingArgon2Adapter(kdf, hmacFactory);
    }

    /// <summary>Records the password buffers a derivation was handed and the keys it handed back.</summary>
    private sealed class RecordingKdf
    {
        /// <summary>The password arrays passed in, by reference.</summary>
        internal List<byte[]> Passwords { get; } = [];

        /// <summary>The derived keys returned, by reference — the arrays the library must clear.</summary>
        internal List<byte[]> DerivedKeys { get; } = [];

        /// <summary>Copies of those keys taken at derivation time.</summary>
        internal List<byte[]> Snapshots { get; } = [];

        internal byte[] Record(byte[] password, byte[] derivedKey)
        {
            Passwords.Add(password);
            DerivedKeys.Add(derivedKey);
            Snapshots.Add((byte[])derivedKey.Clone());
            return derivedKey;
        }
    }

    private sealed class RecordingPbkdf2ServiceFactory(RecordingKdf recorder) : IPbkdf2ServiceFactory
    {
        public IPbkdf2Service CreatePbkdf2Service() => new RecordingPbkdf2Service(recorder);

        private sealed class RecordingPbkdf2Service(RecordingKdf recorder) : IPbkdf2Service
        {
            public byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int keySizeBytes, Pbkdf2Prf prf) =>
                recorder.Record(
                    password,
                    new Pbkdf2ServiceFactory().CreatePbkdf2Service()
                        .DeriveKey(password, salt, iterations, keySizeBytes, prf));
        }
    }

    private sealed class RecordingArgon2ServiceFactory(RecordingKdf recorder) : IArgon2ServiceFactory
    {
        public IArgon2Service CreateArgon2Service() => new RecordingArgon2Service(recorder);

        private sealed class RecordingArgon2Service(RecordingKdf recorder) : IArgon2Service
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
                recorder.Record(
                    password,
                    new Argon2ServiceFactory().CreateArgon2Service().DeriveKey(
                        password, salt, iterations, memorySizeKb, degreeOfParallelism, keySizeBytes, variant, version));
        }
    }

    /// <summary>Records, by reference, every key an HMAC was computed under.</summary>
    private sealed class RecordingHmacServiceFactory : IHmacServiceFactory
    {
        internal List<byte[]> Keys { get; } = [];

        public IHmacService CreateHmacSha1Service(int bufferSize = 4096) => Wrap(bufferSize, "sha1");

        public IHmacService CreateHmacSha256Service(int bufferSize = 4096) => Wrap(bufferSize, "sha256");

        public IHmacService CreateHmacSha512Service(int bufferSize = 4096) => Wrap(bufferSize, "sha512");

        private IHmacService Wrap(int bufferSize, string algorithm)
        {
            HmacServiceFactory real = new();
            IHmacService inner = algorithm switch
            {
                "sha1" => real.CreateHmacSha1Service(bufferSize),
                "sha512" => real.CreateHmacSha512Service(bufferSize),
                _ => real.CreateHmacSha256Service(bufferSize),
            };

            return new RecordingHmacService(inner, Keys);
        }

        private sealed class RecordingHmacService(IHmacService inner, List<byte[]> keys) : IHmacService
        {
            public byte[] ComputeHmac(byte[] data, byte[] key)
            {
                keys.Add(key);
                return inner.ComputeHmac(data, key);
            }

            public Task<byte[]> ComputeHmacAsync(
                Stream data,
                byte[] key,
                IProgress<int>? progress = null,
                CancellationToken cancellationToken = default)
            {
                keys.Add(key);
                return inner.ComputeHmacAsync(data, key, progress, cancellationToken);
            }
        }
    }

    private sealed class RecordingPbkdf2Adapter(RecordingKdf recorder, IHmacServiceFactory hmacServiceFactory)
        : PasswordServiceAdapter
    {
        private readonly Pbkdf2DataEncryptionService _service = new(
            new BlockCipherServiceFactory(),
            new RecordingPbkdf2ServiceFactory(recorder),
            hmacServiceFactory,
            new RandomSource());

        internal override EncryptionMethod Method => EncryptionMethod.Pbkdf2;

        internal override int HeaderLength => 53;

        internal override IReadOnlyList<CostField> CostFields => [];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            byte[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(input, output, cipher, password, TestIterations, progress, cancellationToken);

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            char[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(input, output, cipher, password, TestIterations, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            byte[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            char[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);
    }

    private sealed class RecordingArgon2Adapter(RecordingKdf recorder, IHmacServiceFactory hmacServiceFactory)
        : PasswordServiceAdapter
    {
        private readonly Argon2DataEncryptionService _service = new(
            new BlockCipherServiceFactory(),
            new RecordingArgon2ServiceFactory(recorder),
            hmacServiceFactory,
            new RandomSource());

        internal override EncryptionMethod Method => EncryptionMethod.Argon2;

        internal override int HeaderLength => 61;

        internal override IReadOnlyList<CostField> CostFields => [];

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            byte[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input, output, cipher, password,
                TestArgon2Iterations, TestArgon2MemorySizeKb, TestArgon2DegreeOfParallelism, progress, cancellationToken);

        internal override Task EncryptAsync(
            Stream input,
            Stream output,
            Cipher cipher,
            char[] password,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.EncryptAsync(
                input, output, cipher, password,
                TestArgon2Iterations, TestArgon2MemorySizeKb, TestArgon2DegreeOfParallelism, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            byte[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);

        internal override Task DecryptAsync(
            Stream input,
            Stream output,
            char[] password,
            DataEncryptionLimits? limits = null,
            IProgress<int>? progress = null,
            CancellationToken cancellationToken = default) =>
            _service.DecryptAsync(input, output, password, limits, progress, cancellationToken);
    }
}
