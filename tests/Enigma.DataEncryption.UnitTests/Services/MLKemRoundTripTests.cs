using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Round-trips the ML-KEM method across every cipher, every parameter set and every payload shape, and
/// asserts the stream-level promises the XML docs make: nothing is disposed, nothing needs to be seekable,
/// and progress counts payload bytes only.
/// </summary>
/// <remarks>
/// Two things are specific to this method. The <b>parameter-set byte</b> at offset 5 pushes every later
/// offset one further than RSA's and determines <c>N</c>, so the header shape is asserted at all three sets.
/// And the data key is <b>not generated</b> — it is the encapsulated shared secret — which
/// <see cref="TheNonceComesFromTheRandomSourceAndTheDataKeyDoesNot"/> pins with a random source that refuses
/// any request other than the nonce.
/// </remarks>
/// <param name="keys">The shared key material.</param>
// ReSharper disable once InconsistentNaming
[Collection(MLKemKeyCollection.Name)]
public sealed class MLKemRoundTripTests(MLKemKeyFixture keys)
{
    /// <summary>All four ciphers.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher> Ciphers() => [.. MLKemTestData.AllCiphers];

    /// <summary>The three parameter sets.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<MLKemParameterSet> ParameterSets() => [.. MLKemKeyFixture.AllParameterSets];

    /// <summary>Every cipher against every parameter set — the phase's twelve combinations.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher, MLKemParameterSet> CiphersAndParameterSets()
    {
        TheoryData<Cipher, MLKemParameterSet> data = [];
        foreach (Cipher cipher in MLKemTestData.AllCiphers)
        {
            foreach (MLKemParameterSet parameterSet in MLKemKeyFixture.AllParameterSets)
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
        byte[] plaintext = MLKemTestData.Plaintext(4_096 + 17);

        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), plaintext, cipher, parameterSet);
        byte[] recovered = await MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(parameterSet), container);

        Assert.Equal(plaintext, recovered);
    }

    /// <summary>
    /// The container is exactly the header, the ciphertext and the 128-bit GCM tag — no padding, no trailer
    /// (<c>docs/format.md</c> §4) — and the header records the parameter set it was encapsulated under.
    /// </summary>
    [Theory]
    [MemberData(nameof(CiphersAndParameterSets))]
    public async Task TheContainerIsHeaderPlusCiphertextPlusTag(Cipher cipher, MLKemParameterSet parameterSet)
    {
        byte[] plaintext = MLKemTestData.Plaintext(1_000);

        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), plaintext, cipher, parameterSet);

        Assert.Equal(MLKemTestData.HeaderLengthOf(parameterSet) + plaintext.Length + 16, container.Length);
        Assert.Equal((byte)EncryptionMethod.MLKem, container[2]);
        Assert.Equal(DataEncryptionDefaults.FormatVersion, container[3]);
        Assert.Equal((byte)cipher, container[4]);
        Assert.Equal(MLKemTestData.WireByteOf(parameterSet), container[MLKemTestData.ParameterSetOffset]);
    }

    /// <summary>
    /// The encapsulation length field says what §3.4 tabulates for the parameter set — 768, 1,088 or
    /// 1,568 — which is the field the whole variable-length shape hangs on.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task TheEncapsulationLengthFieldMatchesTheParameterSet(MLKemParameterSet parameterSet)
    {
        int expected = MLKemTestData.EncapsulationLengthOf(parameterSet);

        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), MLKemTestData.Plaintext(300), Cipher.Aes256Gcm, parameterSet);

        Assert.Equal(
            MLKemTestData.LittleEndian(expected),
            container[MLKemTestData.EncapsulationLengthOffset..MLKemTestData.EncapsulationOffset]);
        Assert.Equal(MLKemTestData.HeaderLength(expected) + 300 + 16, container.Length);
    }

    /// <summary>
    /// <b>The default parameter set is ML-KEM-1024</b>, read straight off the produced header rather than
    /// inferred from the signature's default value.
    /// </summary>
    [Fact]
    public async Task TheDefaultParameterSetIsMLKem1024()
    {
        MLKemDataEncryptionService service = MLKemTestData.Service();
        byte[] plaintext = MLKemTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();

        // Note the omitted parameterSet argument: this test is about what the default *is*.
        await service.EncryptAsync(
            input,
            output,
            Cipher.Aes256Gcm,
            keys.PublicKey(MLKemParameterSet.MLKem1024),
            cancellationToken: TestContext.Current.CancellationToken);

        byte[] container = output.ToArray();
        Assert.Equal(0x03, container[MLKemTestData.ParameterSetOffset]);
        Assert.Equal(
            MLKemTestData.LittleEndian(MLKemTestData.EncapsulationLength1024),
            container[MLKemTestData.EncapsulationLengthOffset..MLKemTestData.EncapsulationOffset]);
        Assert.Equal(MLKemTestData.HeaderLengthOf(MLKemParameterSet.MLKem1024) + 64 + 16, container.Length);

        Assert.Equal(
            plaintext,
            await MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(MLKemParameterSet.MLKem1024), container));
    }

    // --- Payload shapes -----------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task RoundTripsAnEmptyPayload(MLKemParameterSet parameterSet)
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), [], Cipher.Aes256Gcm, parameterSet);

        Assert.Equal(MLKemTestData.HeaderLengthOf(parameterSet) + 16, container.Length);
        Assert.Empty(await MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(parameterSet), container));
    }

    [Fact]
    public async Task RoundTripsASinglePayloadByte()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(MLKemParameterSet.MLKem1024), [0x5A]);

        Assert.Equal<byte[]>(
            [0x5A],
            await MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(MLKemParameterSet.MLKem1024), container));
    }

    /// <summary>
    /// An 8 MiB payload, generated rather than materialized, round-tripped and verified byte by byte as it
    /// arrives — the KEM covers the 32-byte shared secret only, so file size is unconstrained by it.
    /// </summary>
    [Fact]
    public async Task RoundTripsALargePayload()
    {
        const int size = 8 * 1024 * 1024;
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024;
        MLKemDataEncryptionService service = MLKemTestData.Service();

        using PatternStream plaintext = new(size);
        using MemoryStream container = new();
        await service.EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.PublicKey(parameterSet), parameterSet, null,
            TestContext.Current.CancellationToken);

        Assert.Equal(MLKemTestData.HeaderLengthOf(parameterSet) + size + 16, container.Length);

        container.Position = 0;
        using PatternVerifyingStream recovered = new();
        await service.DecryptAsync(
            container, recovered, keys.PrivateKey(parameterSet), null, null,
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
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024;

        using PatternStream plaintext = new(size);
        long readWhenFirstPayloadByteWasWritten = -1;
        using CountingSink container = new(
            MLKemTestData.HeaderLengthOf(parameterSet),
            () => readWhenFirstPayloadByteWasWritten = plaintext.BytesRead);

        await MLKemTestData.Service().EncryptAsync(
            plaintext, container, Cipher.Aes256Gcm, keys.PublicKey(parameterSet), parameterSet, null,
            TestContext.Current.CancellationToken);

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
        byte[] plaintext = MLKemTestData.Plaintext(300);
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), plaintext, cipher, parameterSet);

        // A chunk size that is not a divisor of the header length, so the encapsulation is delivered across
        // read boundaries — the tee-ed AAD has to survive that.
        using ForwardOnlyStream input = new(container, maxChunk: 7);
        using MemoryStream output = new();
        await MLKemTestData.Service().DecryptAsync(
            input, output, keys.PrivateKey(parameterSet), null, null, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, output.ToArray());
    }

    /// <summary>Neither stream is disposed, and the caller's position is left where the operation ended.</summary>
    [Fact]
    public async Task NeitherStreamIsDisposed()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        MLKemDataEncryptionService service = MLKemTestData.Service();
        byte[] plaintext = MLKemTestData.Plaintext(64);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.PublicKey(parameterSet), parameterSet, null,
            TestContext.Current.CancellationToken);

        // A disposed MemoryStream throws on these; a live one does not.
        Assert.True(input.CanRead);
        Assert.True(container.CanWrite);
        Assert.Equal(container.Length, container.Position);

        container.Position = 0;
        using MemoryStream output = new();
        await service.DecryptAsync(
            container, output, keys.PrivateKey(parameterSet), null, null,
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
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024;
        MLKemDataEncryptionService service = MLKemTestData.Service();
        byte[] plaintext = MLKemTestData.Plaintext(48);

        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream output = new();
        await output.WriteAsync(preamble, 0, preamble.Length, TestContext.Current.CancellationToken);
        await service.EncryptAsync(
            input, output, Cipher.Aes256Gcm, keys.PublicKey(parameterSet), parameterSet, null,
            TestContext.Current.CancellationToken);

        byte[] written = output.ToArray();
        Assert.Equal(preamble, written[..4]);
        Assert.Equal(0xEC, written[4]);

        output.Position = preamble.Length;
        using MemoryStream recovered = new();
        await service.DecryptAsync(
            output, recovered, keys.PrivateKey(parameterSet), null, null,
            TestContext.Current.CancellationToken);
        Assert.Equal(plaintext, recovered.ToArray());
    }

    // --- Progress -----------------------------------------------------------------------------------

    /// <summary>
    /// Progress totals the payload byte count and excludes the header, on both directions. Were the
    /// 1,606-byte header counted, the sums below would be larger by exactly that.
    /// </summary>
    [Fact]
    public async Task ProgressTotalsThePayloadBytesAndExcludesTheHeader()
    {
        const int size = 10_000;
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024;
        MLKemDataEncryptionService service = MLKemTestData.Service();
        byte[] plaintext = MLKemTestData.Plaintext(size);

        ProgressCollector encryptProgress = new();
        using MemoryStream input = new(plaintext, writable: false);
        using MemoryStream container = new();
        await service.EncryptAsync(
            input, container, Cipher.Aes256Gcm, keys.PublicKey(parameterSet), parameterSet, encryptProgress,
            TestContext.Current.CancellationToken);

        Assert.NotEmpty(encryptProgress.Values);
        Assert.All(encryptProgress.Values, value => Assert.True(value > 0, $"Progress reported {value}."));
        Assert.Equal(size, encryptProgress.Total);

        ProgressCollector decryptProgress = new();
        container.Position = 0;
        using MemoryStream output = new();
        await service.DecryptAsync(
            container, output, keys.PrivateKey(parameterSet), null, decryptProgress,
            TestContext.Current.CancellationToken);

        Assert.NotEmpty(decryptProgress.Values);
        Assert.All(decryptProgress.Values, value => Assert.True(value > 0, $"Progress reported {value}."));
        Assert.Equal(size, decryptProgress.Total);
    }

    // --- The nonce and the shared secret ------------------------------------------------------------

    /// <summary>
    /// A fresh encapsulation and nonce per call: two encryptions of the same plaintext under the same public
    /// key must not produce the same container. Nonce reuse under one key is the classic GCM catastrophe, and
    /// here the shared secret is fresh too — encapsulation draws its own randomness inside Enigma.Core.
    /// </summary>
    [Fact]
    public async Task EachCallDrawsAFreshNonceAndEncapsulation()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024;
        byte[] plaintext = MLKemTestData.Plaintext(64);
        byte[] publicKey = keys.PublicKey(parameterSet);

        byte[] first = await MLKemTestData.EncryptToBytesAsync(publicKey, plaintext, Cipher.Aes256Gcm, parameterSet);
        byte[] second = await MLKemTestData.EncryptToBytesAsync(publicKey, plaintext, Cipher.Aes256Gcm, parameterSet);

        Assert.NotEqual(first, second);
        Assert.NotEqual(
            first[MLKemTestData.NonceOffset..MLKemTestData.EncapsulationLengthOffset],
            second[MLKemTestData.NonceOffset..MLKemTestData.EncapsulationLengthOffset]);
        Assert.NotEqual(
            MLKemTestData.EncapsulationOf(first, MLKemTestData.EncapsulationLength1024),
            MLKemTestData.EncapsulationOf(second, MLKemTestData.EncapsulationLength1024));
    }

    /// <summary>
    /// The nonce comes from the injected source — and <b>nothing else does</b>. The source here refuses every
    /// request that is not nonce-sized, so an implementation that generated its own 32-byte data key instead
    /// of using the encapsulated shared secret would fail rather than quietly produce a container only it can
    /// read.
    /// </summary>
    [Fact]
    public async Task TheNonceComesFromTheRandomSourceAndTheDataKeyDoesNot()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem1024;
        FixedNonceSource randomSource = new(FormatTestData.Nonce());

        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet),
            MLKemTestData.Plaintext(16),
            Cipher.Aes256Gcm,
            parameterSet,
            MLKemTestData.Service(randomSource));

        Assert.Equal(
            FormatTestData.Nonce(),
            container[MLKemTestData.NonceOffset..MLKemTestData.EncapsulationLengthOffset]);
        Assert.Equal(1, randomSource.Requests[DataEncryptionDefaults.NonceSizeBytes]);
        Assert.Single(randomSource.Requests);

        // …and the container's shared secret really is the one its own encapsulation yields, recovered here
        // with Enigma.Core's KEM directly rather than through the service under test.
        byte[] secret = MLKemTestData.Decapsulate(
            MLKemTestData.EncapsulationOf(container, MLKemTestData.EncapsulationLength1024),
            keys.PrivateKey(parameterSet),
            parameterSet);
        Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, secret.Length);
    }

    /// <summary>
    /// The parameter set the service asks Enigma.Core for is the one the caller named on encrypt, and the one
    /// the <i>header</i> names on decrypt — never a default, and never the caller's opinion on the way back.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task TheParameterSetIsTakenFromTheCallerThenFromTheHeader(MLKemParameterSet parameterSet)
    {
        RecordingMLKemServiceFactory recorder = new();
        byte[] plaintext = MLKemTestData.Plaintext(64);

        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet),
            plaintext,
            Cipher.Aes256Gcm,
            parameterSet,
            MLKemTestData.Service(mlKemServiceFactory: recorder));

        Assert.Equal([parameterSet], recorder.RequestedParameterSets);

        RecordingMLKemServiceFactory readerRecorder = new();
        Assert.Equal(
            plaintext,
            await MLKemTestData.DecryptToBytesAsync(
                keys.PrivateKey(parameterSet),
                container,
                service: MLKemTestData.Service(mlKemServiceFactory: readerRecorder)));

        Assert.Equal([parameterSet], readerRecorder.RequestedParameterSets);
    }
}
