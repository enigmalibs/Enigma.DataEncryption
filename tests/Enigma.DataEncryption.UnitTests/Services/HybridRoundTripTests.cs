using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Round-trips the hybrid method across every cipher, every parameter set and every payload shape, and
/// asserts the stream-level promises the XML docs make: nothing is disposed, nothing needs to be seekable,
/// and progress counts payload bytes only.
/// </summary>
/// <remarks>
/// What is specific to this method is that the header carries <b>two</b> variable-length fields, so every
/// offset past the first one moves with the RSA modulus. The round-trips below therefore sweep RSA-2048 and
/// RSA-3072 as well as all three parameter sets, which is what would catch a reader that had hard-coded the
/// second length field's offset.
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(HybridKeyCollection.Name)]
public sealed class HybridRoundTripTests(HybridKeyFixture keys)
{
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;

    /// <summary>All four ciphers.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher> Ciphers() => [.. HybridTestData.AllCiphers];

    /// <summary>The three parameter sets.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<MLKemParameterSet> ParameterSets() => [.. HybridKeyFixture.AllParameterSets];

    /// <summary>Every cipher against every parameter set — the phase's twelve combinations.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher, MLKemParameterSet> CiphersAndParameterSets()
    {
        TheoryData<Cipher, MLKemParameterSet> data = [];
        foreach (Cipher cipher in HybridTestData.AllCiphers)
        {
            foreach (MLKemParameterSet parameterSet in HybridKeyFixture.AllParameterSets)
            {
                data.Add(cipher, parameterSet);
            }
        }

        return data;
    }

    // --- The twelve combinations --------------------------------------------------------------------

    /// <summary>4 ciphers × 3 parameter sets, each recovering the plaintext exactly.</summary>
    [Theory]
    [MemberData(nameof(CiphersAndParameterSets))]
    public async Task RoundTripsExactly(Cipher cipher, MLKemParameterSet parameterSet)
    {
        byte[] plaintext = HybridTestData.Plaintext(4_096 + 17);

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), plaintext, cipher, parameterSet);
        byte[] recovered = await HybridTestData.DecryptToBytesAsync(
            keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), container);

        Assert.Equal(plaintext, recovered);
    }

    /// <summary>
    /// The same, at RSA-3072. The RSA modulus sets <c>N</c>, and <c>N</c> is what every offset after the
    /// first length field depends on — so this is the sweep that a hard-coded 256 would fail.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task RoundTripsAtRsa3072(MLKemParameterSet parameterSet)
    {
        byte[] plaintext = HybridTestData.Plaintext(1_000);

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem3072, keys.MLKemPublicKey(parameterSet), plaintext, Cipher.Aes256Gcm,
            parameterSet);

        Assert.Equal(
            HybridTestData.HeaderLength(384, MLKemTestData.EncapsulationLengthOf(parameterSet))
            + plaintext.Length + 16,
            container.Length);

        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem3072, keys.MLKemPrivateKey(parameterSet), container));
    }

    /// <summary>
    /// The container is exactly the header, the ciphertext and the 128-bit GCM tag — no padding, no trailer
    /// (<c>docs/format.md</c> §4) — and the header records both lengths and the parameter set.
    /// </summary>
    [Theory]
    [MemberData(nameof(CiphersAndParameterSets))]
    public async Task TheContainerIsHeaderPlusCiphertextPlusTag(Cipher cipher, MLKemParameterSet parameterSet)
    {
        byte[] plaintext = HybridTestData.Plaintext(1_000);
        int m = MLKemTestData.EncapsulationLengthOf(parameterSet);

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), plaintext, cipher, parameterSet);

        Assert.Equal(HybridTestData.HeaderLengthOf(parameterSet) + plaintext.Length + 16, container.Length);
        Assert.Equal((byte)EncryptionMethod.Hybrid, container[2]);
        Assert.Equal(DataEncryptionDefaults.FormatVersion, container[3]);
        Assert.Equal((byte)cipher, container[4]);
        Assert.Equal(
            MLKemTestData.WireByteOf(parameterSet), container[HybridTestData.ParameterSetOffset]);
        Assert.Equal(
            HybridTestData.LittleEndian(HybridTestData.WrappedSecretLength2048),
            container[HybridTestData.WrappedSecretLengthOffset..HybridTestData.WrappedSecretOffset]);

        int encapsulationLengthOffset =
            HybridTestData.EncapsulationLengthOffset(HybridTestData.WrappedSecretLength2048);
        Assert.Equal(
            HybridTestData.LittleEndian(m),
            container[encapsulationLengthOffset..(encapsulationLengthOffset + 4)]);
    }

    /// <summary>
    /// <b>The default parameter set is ML-KEM-1024</b>, read straight off the produced header rather than
    /// inferred from the signature's default value.
    /// </summary>
    [Fact]
    public async Task TheDefaultParameterSetIsMLKem1024()
    {
        HybridDataEncryptionService service = HybridTestData.Service();
        byte[] plaintext = HybridTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();

        // Note the omitted parameterSet argument: this test is about what the default *is*.
        await service.EncryptAsync(
            input,
            output,
            Cipher.Aes256Gcm,
            keys.RsaPublicKeyPem,
            keys.MLKemPublicKey(MLKemParameterSet.MLKem1024),
            cancellationToken: TestContext.Current.CancellationToken);

        byte[] container = output.ToArray();
        Assert.Equal(0x03, container[HybridTestData.ParameterSetOffset]);
        Assert.Equal(
            HybridTestData.HeaderLengthOf(MLKemParameterSet.MLKem1024) + 64 + 16, container.Length);

        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(MLKemParameterSet.MLKem1024), container));
    }

    /// <summary>An encrypted RSA private-key PEM opens the container when its passphrase is supplied.</summary>
    [Fact]
    public async Task RoundTripsWithAnEncryptedRsaPrivateKeyPem()
    {
        byte[] plaintext = HybridTestData.Plaintext(256);
        char[] passphrase = keys.PemPassphraseChars();

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.EncryptedPemRsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm,
            Default);

        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.EncryptedRsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container, passphrase));

        // The caller's passphrase array is theirs — untouched.
        Assert.Equal(keys.PemPassphraseChars(), passphrase);
    }

    // --- Payload shapes -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task RoundTripsAnEmptyPayload(MLKemParameterSet parameterSet)
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), [], Cipher.Aes256Gcm, parameterSet);

        Assert.Equal(HybridTestData.HeaderLengthOf(parameterSet) + 16, container.Length);
        Assert.Empty(
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), container));
    }

    [Fact]
    public async Task RoundTripsASinglePayloadByte()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), [0x5A], Cipher.Aes256Gcm, Default);

        Assert.Equal<byte[]>(
            [0x5A],
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container));
    }

    /// <summary>
    /// An 8 MiB payload, generated rather than materialized, verified byte by byte as it arrives. Both
    /// public-key operations cover 32-byte secrets only, so file size is unconstrained by either.
    /// </summary>
    [Fact]
    public async Task RoundTripsALargePayload()
    {
        const int size = 8 * 1024 * 1024;
        HybridDataEncryptionService service = HybridTestData.Service();

        using PatternStream plaintext = new(size);
        using MemoryStream container = new();
        await service.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
            Default, null, TestContext.Current.CancellationToken);

        Assert.Equal(HybridTestData.HeaderLengthOf(Default) + size + 16, container.Length);

        container.Position = 0;
        using PatternVerifyingStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
            TestContext.Current.CancellationToken);

        Assert.Equal(size, recovered.BytesWritten);
    }

    /// <summary>
    /// The payload is streamed, not buffered: ciphertext reaches the output while the input still has bytes
    /// left to give.
    /// </summary>
    [Fact]
    public async Task StreamsRatherThanBufferingTheWholePayload()
    {
        const int size = 8 * 1024 * 1024;

        using PatternStream plaintext = new(size);
        long readWhenFirstPayloadByteWasWritten = -1;
        using CountingSink container = new(
            HybridTestData.HeaderLengthOf(Default),
            () => readWhenFirstPayloadByteWasWritten = plaintext.BytesRead);

        await HybridTestData.Service().EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default),
            Default, null, TestContext.Current.CancellationToken);

        Assert.True(
            readWhenFirstPayloadByteWasWritten is > 0 and < size,
            $"The first payload write happened after {readWhenFirstPayloadByteWasWritten} of {size} input bytes had been read; a streaming implementation writes before the input is exhausted.");
    }

    // --- Stream contract ----------------------------------------------------------------------------

    /// <summary>Decryption must not require a seekable stream (<c>docs/format.md</c> §7.2).</summary>
    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task DecryptsFromANonSeekableDripFedStream(Cipher cipher)
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem768;
        byte[] plaintext = HybridTestData.Plaintext(300);
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), plaintext, cipher, parameterSet);

        // A chunk size that divides neither variable-length field, so both are delivered across read
        // boundaries — the tee-ed AAD has to survive that twice over.
        using ForwardOnlyStream input = new(container, maxChunk: 7);
        using MemoryStream output = new();
        await HybridTestData.Service().DecryptAsync(
            input, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), null, null, null,
            TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, output.ToArray());
    }

    /// <summary>Neither stream is disposed, and the caller's position is left where the operation ended.</summary>
    [Fact]
    public async Task NeitherStreamIsDisposed()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        HybridDataEncryptionService service = HybridTestData.Service();
        byte[] plaintext = HybridTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet),
            parameterSet, null, TestContext.Current.CancellationToken);

        // A disposed MemoryStream throws on these; a live one does not.
        Assert.True(input.CanRead);
        Assert.True(container.CanWrite);
        Assert.Equal(container.Length, container.Position);

        container.Position = 0;
        using MemoryStream output = new();
        await service.DecryptAsync(
            container, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), null, null, null,
            TestContext.Current.CancellationToken);

        Assert.True(container.CanRead);
        Assert.True(output.CanWrite);
    }

    /// <summary>
    /// The container is written at the output stream's current position, not at its start — so a caller may
    /// prepend their own framing.
    /// </summary>
    [Fact]
    public async Task WritesAtTheOutputStreamsCurrentPosition()
    {
        byte[] preamble = [0xDE, 0xAD, 0xBE, 0xEF];
        HybridDataEncryptionService service = HybridTestData.Service();
        byte[] plaintext = HybridTestData.Plaintext(48);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await output.WriteAsync(preamble, 0, preamble.Length, TestContext.Current.CancellationToken);
        await service.EncryptAsync(
            input, output, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), Default,
            null, TestContext.Current.CancellationToken);

        byte[] written = output.ToArray();
        Assert.Equal(preamble, written[..4]);
        Assert.Equal(0xEC, written[4]);

        output.Position = preamble.Length;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            output, recovered, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null, null,
            TestContext.Current.CancellationToken);
        Assert.Equal(plaintext, recovered.ToArray());
    }

    // --- Progress -----------------------------------------------------------------------------------

    /// <summary>
    /// Progress totals the payload byte count and excludes the header, in both directions. Were the
    /// 1,866-byte header counted, the sums below would be larger by exactly that.
    /// </summary>
    [Fact]
    public async Task ProgressTotalsThePayloadBytesAndExcludesTheHeader()
    {
        const int size = 10_000;
        HybridDataEncryptionService service = HybridTestData.Service();
        byte[] plaintext = HybridTestData.Plaintext(size);

        ProgressCollector encryptProgress = new();
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), Default,
            encryptProgress, TestContext.Current.CancellationToken);

        Assert.NotEmpty(encryptProgress.Values);
        Assert.All(encryptProgress.Values, value => Assert.True(value > 0, $"Progress reported {value}."));
        Assert.Equal(size, encryptProgress.Total);

        ProgressCollector decryptProgress = new();
        container.Position = 0;
        using MemoryStream output = new();
        await service.DecryptAsync(
            container, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), null, null,
            decryptProgress, TestContext.Current.CancellationToken);

        Assert.NotEmpty(decryptProgress.Values);
        Assert.All(decryptProgress.Values, value => Assert.True(value > 0, $"Progress reported {value}."));
        Assert.Equal(size, decryptProgress.Total);
    }

    // --- The nonce, the secrets and the ciphertexts --------------------------------------------------

    /// <summary>
    /// Every call draws a fresh nonce, a fresh RSA-half secret and a fresh encapsulation, so two
    /// encryptions of the same plaintext under the same key pair differ in all three. Nonce reuse under one
    /// key is the classic GCM catastrophe, and here the data key is fresh as well because both of its
    /// inputs are.
    /// </summary>
    [Fact]
    public async Task EachCallDrawsAFreshNonceSecretAndEncapsulation()
    {
        byte[] plaintext = HybridTestData.Plaintext(64);
        const int m = MLKemTestData.EncapsulationLength1024;

        byte[] first = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);
        byte[] second = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);

        Assert.NotEqual(first, second);
        Assert.NotEqual(
            first[HybridTestData.NonceOffset..HybridTestData.WrappedSecretLengthOffset],
            second[HybridTestData.NonceOffset..HybridTestData.WrappedSecretLengthOffset]);
        Assert.NotEqual(HybridTestData.WrappedSecretOf(first), HybridTestData.WrappedSecretOf(second));
        Assert.NotEqual(
            HybridTestData.EncapsulationOf(first, m), HybridTestData.EncapsulationOf(second, m));
    }

    /// <summary>
    /// The random source is asked for exactly two things — the nonce and the 32-byte RSA-half secret — and
    /// nothing else. The ML-KEM half draws no randomness through this seam: encapsulation produces its own
    /// secret inside Enigma.Core, so a service that generated a third value here would be inventing key
    /// material the format has no field for.
    /// </summary>
    [Fact]
    public async Task TheRandomSourceSuppliesTheNonceAndTheRsaSecretAndNothingElse()
    {
        FixedDataKeyAndNonceSource randomSource = new(FormatTestData.DataKey(), FormatTestData.Nonce());

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem,
            keys.MLKemPublicKey(Default),
            HybridTestData.Plaintext(16),
            Cipher.Aes256Gcm,
            Default,
            HybridTestData.Service(randomSource));

        Assert.Equal(
            FormatTestData.Nonce(),
            container[HybridTestData.NonceOffset..HybridTestData.WrappedSecretLengthOffset]);
        Assert.Equal(1, randomSource.Requests[DataEncryptionDefaults.NonceSizeBytes]);
        Assert.Equal(1, randomSource.Requests[DataEncryptionDefaults.DataKeySizeBytes]);
        Assert.Equal(2, randomSource.Requests.Count);

        // The RSA field really carries the value the source handed out.
        Assert.Equal(
            FormatTestData.DataKey(),
            HybridTestData.UnwrapOaep(
                HybridTestData.WrappedSecretOf(container), keys.RsaPrivateKeyPem));
    }

    /// <summary>
    /// The parameter set the service asks Enigma.Core for is the one the caller named on encrypt, and the
    /// one the <i>header</i> names on decrypt — never a default, and never the caller's opinion on the way
    /// back.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task TheParameterSetIsTakenFromTheCallerThenFromTheHeader(MLKemParameterSet parameterSet)
    {
        RecordingMLKemServiceFactory recorder = new();
        byte[] plaintext = HybridTestData.Plaintext(64);

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem,
            keys.MLKemPublicKey(parameterSet),
            plaintext,
            Cipher.Aes256Gcm,
            parameterSet,
            HybridTestData.Service(mlKemServiceFactory: recorder));

        Assert.Equal([parameterSet], recorder.RequestedParameterSets);

        RecordingMLKemServiceFactory readerRecorder = new();
        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem,
                keys.MLKemPrivateKey(parameterSet),
                container,
                service: HybridTestData.Service(mlKemServiceFactory: readerRecorder)));

        Assert.Equal([parameterSet], readerRecorder.RequestedParameterSets);
    }

    /// <summary>
    /// The data key really is the combination of both transported secrets — checked by recovering each
    /// secret independently of the service and running the combiner over them, then decrypting the payload
    /// with the result through the platform's AES-GCM.
    /// </summary>
    /// <remarks>
    /// This is the round-trip counterpart of <c>HybridKeyCombinerTests</c>: there the combiner is shown to
    /// depend on all four inputs, here the service is shown to actually be using it on the container it
    /// writes.
    /// </remarks>
    [Fact]
    public async Task TheContainersDataKeyIsTheCombinationOfBothTransportedSecrets()
    {
        byte[] plaintext = HybridTestData.Plaintext(128);
        const int m = MLKemTestData.EncapsulationLength1024;

        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);

        byte[] wrapped = HybridTestData.WrappedSecretOf(container);
        byte[] encapsulation = HybridTestData.EncapsulationOf(container, m);

        byte[] rsaSecret = HybridTestData.UnwrapOaep(wrapped, keys.RsaPrivateKeyPem);
        byte[] kemSecret = HybridTestData.Decapsulate(
            encapsulation, keys.MLKemPrivateKey(Default), Default);

        byte[] dataKey = GoldenVectorPrimitives.HybridDataKey(
            rsaSecret, kemSecret, wrapped, encapsulation);

        int headerLength = HybridTestData.HeaderLengthOf(Default);
        byte[] header = container[..headerLength];
        byte[] nonce = container[HybridTestData.NonceOffset..HybridTestData.WrappedSecretLengthOffset];

        // The key-confirmation tag over the combined key is the one in the header...
        Assert.Equal(
            GoldenVectorPrimitives.KeyConfirmationTag(
                dataKey, header[..(headerLength - DataEncryptionDefaults.KeyConfirmationTagSizeBytes)]),
            header[(headerLength - DataEncryptionDefaults.KeyConfirmationTagSizeBytes)..]);

        // ...and the payload really is AES-GCM under it, with the header as associated data.
        Assert.Equal(
            GoldenVectorPrimitives.AesGcmPayload(dataKey, nonce, header, plaintext),
            container[headerLength..]);
    }
}
