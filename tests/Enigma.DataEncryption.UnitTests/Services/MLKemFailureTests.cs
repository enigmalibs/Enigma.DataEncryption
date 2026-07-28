using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The failure half of the ML-KEM method: the wrong private key — the case this whole construction was
/// designed around — an edited header, a tampered payload, and an encapsulation length field out of bounds.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the phase the key-confirmation tag exists for.</b> FIPS 203 <i>implicit rejection</i> means
/// decapsulating with a well-formed but wrong private key <b>succeeds</b>, returning a different 32-byte
/// secret — <see cref="ImplicitRejectionMeansDecapsulationItselfCannotDetectTheWrongKey"/> demonstrates that
/// against Enigma.Core directly, so the premise is established rather than assumed. Without the tag the only
/// signal would be the GCM tag at the very end of the stream;
/// <see cref="TheWrongPrivateKeyFailsBeforeThePayloadIsRead"/> proves the tag gets there first, with a payload
/// stream that throws if it is touched at all.
/// </para>
/// <para>
/// The second theme is that an out-of-bounds encapsulation length is rejected <b>before the private key is
/// touched</b> — proved with a KEM factory that throws if it is used.
/// </para>
/// <para>
/// The third is the amended row of <c>docs/format.md</c> §9: Enigma.Core reports a malformed private key, a
/// key for another parameter set, and a container whose parameter-set byte was edited as the <i>same</i>
/// <see cref="CryptographicException"/> from the <i>same</i> <c>Decapsulate</c> call. Two of those point in
/// opposite directions — one is the caller's fault, one the file's — so all of them are reported as
/// <see cref="DataDecryptionException"/> rather than guessed at from message text.
/// </para>
/// </remarks>
/// <param name="keys">The shared key material.</param>
// ReSharper disable once InconsistentNaming
[Collection(MLKemKeyCollection.Name)]
public sealed class MLKemFailureTests(MLKemKeyFixture keys)
{
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;
    private const int DefaultN = MLKemTestData.EncapsulationLength1024;

    /// <summary>All four ciphers.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher> Ciphers() => [.. MLKemTestData.AllCiphers];

    /// <summary>The three parameter sets.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<MLKemParameterSet> ParameterSets() => [.. MLKemKeyFixture.AllParameterSets];

    /// <summary>Every named field of the ML-KEM header, by offset (ML-KEM-1024, so <c>N</c> = 1,568).</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string, int> HeaderFields() => new()
    {
        { "magic byte 0", 0 },
        { "magic byte 1", 1 },
        { "method", 2 },
        { "format version", 3 },
        { "cipher", 4 },
        { "parameter set", 5 },
        { "nonce (first byte)", 6 },
        { "nonce (last byte)", 17 },
        { "encapsulation length (first byte)", 18 },
        { "encapsulation length (last byte)", 21 },
        { "encapsulation (first byte)", 22 },
        { "encapsulation (middle byte)", 22 + (DefaultN / 2) },
        { "encapsulation (last byte)", 22 + DefaultN - 1 },
        { "key-confirmation tag (first byte)", 22 + DefaultN },
        { "key-confirmation tag (last byte)", MLKemTestData.HeaderLength(DefaultN) - 1 },
    };

    // --- Implicit rejection, and what catches it ----------------------------------------------------

    /// <summary>
    /// The premise of this phase, established against Enigma.Core rather than assumed: decapsulating with a
    /// well-formed private key of the <b>same</b> parameter set never fails. It returns a different 32-byte
    /// secret and reports nothing, which is precisely why a container needs the key-confirmation tag.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public void ImplicitRejectionMeansDecapsulationItselfCannotDetectTheWrongKey(MLKemParameterSet parameterSet)
    {
        (byte[] encapsulation, byte[] right) = MLKemTestData.Encapsulate(keys.PublicKey(parameterSet), parameterSet);

        byte[] wrong = MLKemTestData.Decapsulate(
            encapsulation, keys.UnrelatedPrivateKey(parameterSet), parameterSet);

        Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, wrong.Length);
        Assert.NotEqual(right, wrong);
    }

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task TheWrongPrivateKeyIsADecryptionError(Cipher cipher)
    {
        byte[] plaintext = MLKemTestData.Plaintext(256);
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), plaintext, cipher, Default);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.UnrelatedPrivateKey(Default), container));

        // …and the other way round, so neither key is special.
        byte[] unrelatedContainer = await MLKemTestData.EncryptToBytesAsync(
            keys.UnrelatedPublicKey(Default), plaintext, cipher, Default);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), unrelatedContainer));
    }

    /// <summary>
    /// <b>The headline assertion of this phase.</b> A wrong ML-KEM private key is rejected while the
    /// container's payload is still untouched — by the key-confirmation tag, because decapsulation succeeded.
    /// The payload here is a stream that throws if it is read at all, which turns "before a single payload
    /// byte is read" (<c>docs/format.md</c> §6.2) from a claim into a test. The exception message is checked
    /// too, so it is demonstrably the tag and not some earlier accident.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task TheWrongPrivateKeyFailsBeforeThePayloadIsRead(MLKemParameterSet parameterSet)
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), MLKemTestData.Plaintext(8_192), Cipher.Aes256Gcm, parameterSet);

        using PoisonedPayloadStream input = new(container[..MLKemTestData.HeaderLengthOf(parameterSet)]);
        using MemoryStream output = new();

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.Service().DecryptAsync(
                input, output, keys.UnrelatedPrivateKey(parameterSet),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("key-confirmation tag", exception.Message);
        Assert.False(input.PayloadWasRead);
        Assert.Equal(0, output.Length);
    }

    /// <summary>The right key, by contrast, does read the payload — the stream double is not the reason above.</summary>
    [Fact]
    public async Task TheRightPrivateKeyDoesReachThePayload()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);

        using PoisonedPayloadStream input = new(container[..MLKemTestData.HeaderLengthOf(Default)]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<IOException>(
            () => MLKemTestData.Service().DecryptAsync(
                input, output, keys.PrivateKey(Default),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.True(input.PayloadWasRead);
    }

    /// <summary>
    /// A private key for a <b>different parameter set</b> cannot even be decapsulated with — the lengths
    /// disagree — so this one fails a step earlier than the wrong-key case above, and lands in the same place.
    /// Per the amended §9 it is a decryption error rather than an argument error, because Enigma.Core reports
    /// it identically to a container whose parameter-set byte was edited.
    /// </summary>
    [Fact]
    public async Task APrivateKeyOfADifferentParameterSetIsADecryptionError()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);

        foreach (MLKemParameterSet other in new[] { MLKemParameterSet.MLKem512, MLKemParameterSet.MLKem768 })
        {
            DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(other), container));

            Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
        }
    }

    /// <summary>
    /// A private key that is merely the wrong length is the same story: a decryption error carrying
    /// Enigma.Core's own diagnosis, not an <see cref="ArgumentException"/>. This is the clause of the
    /// interface's XML docs that PHASE04 amended, and it is asserted here so the amendment is not just prose.
    /// </summary>
    [Fact]
    public async Task APrivateKeyOfTheWrongLengthIsADecryptionErrorWithTheCauseInside()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);
        byte[] right = keys.PrivateKey(Default);

        foreach (byte[] key in new[] { new byte[1], new byte[right.Length - 1], new byte[right.Length + 1] })
        {
            DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
                () => MLKemTestData.DecryptToBytesAsync(key, container));

            Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
        }
    }

    /// <summary>
    /// The hostile-sender case: an encapsulation that decapsulates perfectly, in a header whose tag was
    /// computed under a <i>different</i> secret. Only the key-confirmation tag can catch this, and it does so
    /// without reading the payload.
    /// </summary>
    [Fact]
    public async Task AHeaderTaggedUnderAnotherSecretIsCaughtByKeyConfirmation()
    {
        (byte[] encapsulation, _) = MLKemTestData.Encapsulate(keys.PublicKey(Default), Default);
        byte[] header = await MLKemTestData.BuildHeaderAsync(
            Default, encapsulation, FormatTestData.Sequence(0xA0, DataEncryptionDefaults.DataKeySizeBytes));

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.Service().DecryptAsync(
                input, output, keys.PrivateKey(Default),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("key-confirmation tag", exception.Message);
        Assert.False(input.PayloadWasRead);
    }

    // --- The caller's public key ---------------------------------------------------------------------

    /// <summary>
    /// An unusable public key is an argument error, not a container error — the encrypt side has no ambiguity
    /// to resolve, because <c>Encapsulate</c> takes the public key and nothing else (§9).
    /// </summary>
    [Fact]
    public async Task AnUnusablePublicKeyIsAnArgumentError()
    {
        byte[] plaintext = MLKemTestData.Plaintext(64);
        byte[] right = keys.PublicKey(Default);

        foreach (byte[] key in new[]
                 {
                     new byte[1],
                     new byte[right.Length - 1],
                     new byte[right.Length + 1],
                     keys.PublicKey(MLKemParameterSet.MLKem512),
                 })
        {
            ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
                () => MLKemTestData.EncryptToBytesAsync(key, plaintext, Cipher.Aes256Gcm, Default));

            Assert.Equal("publicKey", exception.ParamName);
            Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
        }
    }

    /// <summary>An unusable public key leaves the output stream untouched — the encapsulation precedes every write.</summary>
    [Fact]
    public async Task AnUnusablePublicKeyWritesNothing()
    {
        using MemoryStream input = new(MLKemTestData.Plaintext(64), writable: false);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<ArgumentException>(
            () => MLKemTestData.Service().EncryptAsync(
                input, output, Cipher.Aes256Gcm, new byte[7], Default, null,
                TestContext.Current.CancellationToken));

        Assert.Equal(0, output.Length);
    }

    /// <summary>
    /// A public key of the right length for another parameter set is refused under the one the caller named —
    /// so the parameter set and the key cannot silently disagree.
    /// </summary>
    [Fact]
    public async Task APublicKeyForAnotherParameterSetIsRefused()
    {
        byte[] plaintext = MLKemTestData.Plaintext(64);

        foreach (MLKemParameterSet declared in MLKemKeyFixture.AllParameterSets)
        {
            foreach (MLKemParameterSet actual in MLKemKeyFixture.AllParameterSets)
            {
                if (declared == actual) continue;

                ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
                    () => MLKemTestData.EncryptToBytesAsync(
                        keys.PublicKey(actual), plaintext, Cipher.Aes256Gcm, declared));

                Assert.Equal("publicKey", exception.ParamName);
            }
        }
    }

    // --- A tampered payload -------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task AFlippedPayloadBitIsADecryptionError(Cipher cipher)
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(256), cipher, Default);

        byte[] tampered = FormatTestData.WithFlippedBit(container, MLKemTestData.HeaderLengthOf(Default) * 8);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), tampered));
    }

    /// <summary>Anywhere in the payload, including the GCM tag that closes it.</summary>
    [Fact]
    public async Task AFlippedBitAnywhereInThePayloadIsADecryptionError()
    {
        int headerLength = MLKemTestData.HeaderLengthOf(Default);
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(200), Cipher.Aes256Gcm, Default);

        foreach (int offset in new[]
                 {
                     headerLength,            // first ciphertext byte
                     headerLength + 100,      // the middle of the ciphertext
                     container.Length - 17,   // last ciphertext byte
                     container.Length - 16,   // first byte of the GCM tag
                     container.Length - 1,    // last byte of the GCM tag
                 })
        {
            byte[] tampered = FormatTestData.WithFlippedBit(container, offset * 8);

            await Assert.ThrowsAsync<DataDecryptionException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), tampered));
        }
    }

    [Fact]
    public async Task ATruncatedOrExtendedPayloadIsADecryptionError()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(200), Cipher.Aes256Gcm, Default);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), container[..^8]));

        // The payload removed entirely: the GCM tag is gone, so authentication cannot succeed.
        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(
                keys.PrivateKey(Default), container[..MLKemTestData.HeaderLengthOf(Default)]));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), [.. container, 0x00]));
    }

    // --- An edited header ---------------------------------------------------------------------------

    /// <summary>
    /// Every named field of the header, edited in turn. The outcome is always one of the two documented
    /// exceptions: <see cref="DataEncryptionFormatException"/> where the edit makes the header structurally
    /// invalid, <see cref="DataDecryptionException"/> where it stays parseable and decapsulation, the
    /// key-confirmation tag or the GCM AAD catches it.
    /// </summary>
    [Theory]
    [MemberData(nameof(HeaderFields))]
    public async Task EditingAnyHeaderFieldIsDetected(string field, int offset)
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(128), Cipher.Aes256Gcm, Default);
        byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

        DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), edited));

        Assert.True(
            exception is DataEncryptionFormatException or DataDecryptionException,
            $"Editing the {field} at offset {offset} raised {exception.GetType().Name}.");
    }

    /// <summary>
    /// And every byte of the header, not only the fields a hand-written list happens to name. ML-KEM-512 is
    /// used so the sweep is 806 cases rather than 1,606 — the shape is identical, only <c>N</c> differs.
    /// </summary>
    [Fact]
    public async Task EditingAnyHeaderByteIsDetected()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, parameterSet);

        for (int offset = 0; offset < MLKemTestData.HeaderLengthOf(parameterSet); offset++)
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(parameterSet), edited));

            Assert.True(
                exception is DataEncryptionFormatException or DataDecryptionException,
                $"Flipping a bit at header offset {offset} raised {exception.GetType().Name}.");
        }
    }

    /// <summary>The structural fields are format errors specifically, not merely "some" error.</summary>
    [Fact]
    public async Task EditingTheMagicOrTheVersionIsAFormatError()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);

        foreach (int offset in new[] { 0, 1, 3 })
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), edited));
        }
    }

    /// <summary>
    /// Editing the cipher byte to <b>another valid cipher</b>: the header still parses and the encapsulation
    /// is intact, so what catches it is the key-confirmation tag — the header is covered by it (§6).
    /// </summary>
    [Fact]
    public async Task EditingTheCipherByteToAnotherValidCipherIsADecryptionError()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);

        byte[] edited = FormatTestData.WithByteAt(container, 4, (byte)Cipher.Serpent256Gcm);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), edited));
    }

    [Fact]
    public async Task EditingTheCipherByteToAnUndefinedValueIsAFormatError()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);

        foreach (byte cipherByte in new byte[] { 0x00, 0x05, 0xFF })
        {
            byte[] edited = FormatTestData.WithByteAt(container, 4, cipherByte);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), edited));
        }
    }

    // --- The parameter-set byte ---------------------------------------------------------------------

    /// <summary>
    /// An undefined parameter-set byte is a format error — and one raised <b>before the private key is
    /// touched</b>, which the poisoned KEM factory proves. Note <c>0x00</c> in particular: the wire encoding
    /// is 1-based precisely so a zero-filled header cannot parse (§3.4).
    /// </summary>
    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x04)]
    [InlineData((byte)0x05)]
    [InlineData((byte)0x7F)]
    [InlineData((byte)0xFF)]
    public async Task AnUndefinedParameterSetByteIsAFormatErrorWithNoDecapsulation(byte parameterSetByte)
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);
        byte[] edited = FormatTestData.WithByteAt(container, MLKemTestData.ParameterSetOffset, parameterSetByte);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => MLKemTestData.DecryptToBytesAsync(
                keys.PrivateKey(Default),
                edited,
                service: MLKemTestData.Service(mlKemServiceFactory: new PoisonedMLKemServiceFactory())));

        Assert.Contains("parameter-set byte", exception.Message);
    }

    /// <summary>
    /// The parameter-set byte edited to a <b>different valid value</b>. The plan left the outcome open; what
    /// the implementation produces is <see cref="DataDecryptionException"/>, and here is why: the header still
    /// parses, and the encapsulation length still passes its bounds check — but the reader then builds a KEM
    /// for the parameter set the byte now claims, and hands it a ciphertext and a private key sized for the
    /// real one. Every parameter set has a distinct ciphertext and key length (768/1,088/1,568 and
    /// 1,632/2,400/3,168), so decapsulation cannot succeed, and its failure is wrapped per §9. Were the
    /// lengths ever to coincide, the key-confirmation tag — which covers this byte — would catch it instead.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task EditingTheParameterSetByteToAnotherValidValueIsADecryptionError(MLKemParameterSet written)
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(written), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, written);

        foreach (MLKemParameterSet claimed in MLKemKeyFixture.AllParameterSets)
        {
            if (claimed == written) continue;

            byte[] edited = FormatTestData.WithByteAt(
                container, MLKemTestData.ParameterSetOffset, MLKemTestData.WireByteOf(claimed));

            DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(written), edited));

            Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
        }
    }

    // --- Method and stream shape --------------------------------------------------------------------

    /// <summary>
    /// Handing another method's container to the ML-KEM service is a format error, not a misparse — each
    /// service reads only its own method byte (<c>docs/format.md</c> §2.2) — and the same holds in reverse.
    /// </summary>
    [Fact]
    public async Task AnotherMethodsContainerIsAFormatError()
    {
        byte[] plaintext = MLKemTestData.Plaintext(64);
        byte[] mlKemContainer = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);
        byte[] pbkdf2Container = await PasswordTestData.EncryptToBytesAsync(
            PasswordServiceAdapter.Create(PasswordMethod.Pbkdf2), plaintext);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), pbkdf2Container));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => PasswordTestData.DecryptToBytesAsync(
                PasswordServiceAdapter.Create(PasswordMethod.Pbkdf2), mlKemContainer));
    }

    [Fact]
    public async Task AnEmptyOrTinyStreamIsAFormatError()
    {
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), []));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), [0xEC]));
    }

    /// <summary>A header cut short anywhere is a format error, at every offset.</summary>
    [Fact]
    public async Task ATruncatedHeaderIsAFormatErrorAtEveryOffset()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, parameterSet);

        for (int length = 0; length < MLKemTestData.HeaderLengthOf(parameterSet); length++)
        {
            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(parameterSet), container[..length]));
        }
    }

    // --- The encapsulation length field -------------------------------------------------------------

    /// <summary>
    /// The length field at one over its cap, at zero, negative, and at both extremes of <see cref="int"/> —
    /// rejected as a format error, and <b>with no KEM operation attempted</b>: the service is wired with a
    /// factory that throws if it is ever reached.
    /// </summary>
    /// <remarks>
    /// This is what the limits are for (<c>docs/format.md</c> §8). <see cref="int.MaxValue"/> is the pointed
    /// case — a claim of 2 GiB, which must cost a comparison to reject rather than an allocation to survive.
    /// </remarks>
    [Fact]
    public async Task AnEncapsulationLengthOutOfBoundsIsAFormatErrorWithNoDecapsulation()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);
        MLKemDataEncryptionService reader = MLKemTestData.Service(
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());

        foreach (int value in new[]
                 {
                     DataEncryptionLimits.Default.MaxEncapsulationLength + 1, 0, -1, int.MinValue, int.MaxValue,
                 })
        {
            byte[] edited = FormatTestData.WithInt32At(container, MLKemTestData.EncapsulationLengthOffset, value);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), edited, service: reader));
        }
    }

    /// <summary>A zero encapsulation length is named by the field name that rejected it.</summary>
    [Fact]
    public async Task AZeroEncapsulationLengthNamesTheField()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);
        byte[] edited = FormatTestData.WithInt32At(container, MLKemTestData.EncapsulationLengthOffset, 0);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), edited));

        Assert.Contains("ML-KEM encapsulation length", exception.Message);
    }

    /// <summary>
    /// A length that is within the cap but longer than the stream can satisfy: the stream ends inside the
    /// header, which is a format error too.
    /// </summary>
    [Fact]
    public async Task AnEncapsulationLengthBeyondTheEndOfTheStreamIsAFormatError()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);

        foreach (int value in new[] { DefaultN + 1_024, DataEncryptionLimits.Default.MaxEncapsulationLength })
        {
            byte[] edited = FormatTestData.WithInt32At(container, MLKemTestData.EncapsulationLengthOffset, value);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), edited));
        }
    }

    /// <summary>
    /// Tightened limits are honoured: a container written with a legal encapsulation length is refused by a
    /// reader whose bound is stricter than the header's value — and refused before the private key is used.
    /// </summary>
    [Fact]
    public async Task TightenedLimitsRejectAnOtherwiseValidHeader()
    {
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), MLKemTestData.Plaintext(64), Cipher.Aes256Gcm, Default);
        DataEncryptionLimits strict = new() { MaxEncapsulationLength = DefaultN - 1 };

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => MLKemTestData.DecryptToBytesAsync(
                keys.PrivateKey(Default),
                container,
                limits: strict,
                service: MLKemTestData.Service(mlKemServiceFactory: new PoisonedMLKemServiceFactory())));
    }

    /// <summary>A limit exactly at the encapsulation length is legal — the cap includes its own value.</summary>
    [Fact]
    public async Task ALimitExactlyAtTheEncapsulationLengthIsAccepted()
    {
        byte[] plaintext = MLKemTestData.Plaintext(64);
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);
        DataEncryptionLimits atCap = new() { MaxEncapsulationLength = DefaultN };

        Assert.Equal(
            plaintext,
            await MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(Default), container, limits: atCap));
    }

    /// <summary>And the default limits accept what the service itself writes, at every parameter set.</summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task TheDefaultLimitsAcceptTheServicesOwnOutput(MLKemParameterSet parameterSet)
    {
        byte[] plaintext = MLKemTestData.Plaintext(64);
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), plaintext, Cipher.Aes256Gcm, parameterSet);

        Assert.Equal(
            plaintext,
            await MLKemTestData.DecryptToBytesAsync(
                keys.PrivateKey(parameterSet), container, limits: DataEncryptionLimits.Default));
    }

    /// <summary>
    /// Nothing above ever surfaces an exception type the contract does not name — no
    /// <see cref="NullReferenceException"/>, no indexing failure, no unwrapped Enigma.Core exception.
    /// </summary>
    /// <remarks>
    /// The systematic sweep across all four methods lives in PHASE05; this is the ML-KEM slice of it, so a
    /// regression here is caught in the phase that introduced it. The credential is valid throughout, so only
    /// container errors are admissible outcomes.
    /// </remarks>
    [Fact]
    public async Task NoCorruptionEverEscapesTheDocumentedExceptionTypes()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        byte[] container = await MLKemTestData.EncryptToBytesAsync(
            keys.PublicKey(parameterSet), MLKemTestData.Plaintext(32), Cipher.Aes256Gcm, parameterSet);

        List<byte[]> corrupted = [];
        for (int offset = 0; offset < container.Length; offset++)
        {
            corrupted.Add(FormatTestData.WithByteAt(container, offset, 0x00));
            corrupted.Add(FormatTestData.WithByteAt(container, offset, 0xFF));
        }

        for (int length = 0; length <= container.Length; length++)
        {
            corrupted.Add(container[..length]);
        }

        foreach (byte[] candidate in corrupted)
        {
            try
            {
                await MLKemTestData.DecryptToBytesAsync(keys.PrivateKey(parameterSet), candidate);
            }
            catch (DataEncryptionFormatException)
            {
                // Documented.
            }
            catch (DataDecryptionException)
            {
                // Documented.
            }
        }
    }
}
