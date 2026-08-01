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
/// The failure half of the hybrid method — and, above everything else in it, the two tests that show
/// <b>both</b> transported secrets genuinely reach the data key.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why those two tests are the point of this suite.</b> A combiner that silently ignored one of its two
/// secrets would round-trip perfectly and pass every other test here — while reducing the method to
/// whichever half it still used, which is the one failure this whole feature exists to prevent. The plan
/// asked for "wrong RSA key, right ML-KEM key" and "right RSA key, wrong ML-KEM key", and both are below.
/// </para>
/// <para>
/// <b>Only one of that pair actually isolates a secret, though, and the suite says so rather than pretending
/// otherwise.</b> A wrong <i>RSA private key</i> is caught by OAEP before key confirmation is reached, so it
/// would fail even against a combiner that ignored the RSA secret entirely. A wrong <i>ML-KEM private key</i>
/// is different: implicit rejection means its decapsulation succeeds, the ciphertexts are unchanged, and only
/// the secret differs — so that one is a genuine isolation test. To get the same strength for the RSA half,
/// <see cref="TheRsaSecretContributesToTheDataKey"/> builds a hostile-sender container instead: the header is
/// sealed under a data key combined from a <i>different</i> RSA secret while the transcript stays byte-identical.
/// Between the two, each secret is shown to matter with everything else held fixed.
/// </para>
/// <para>
/// The rest is what the other public-key methods already have, doubled where the hybrid doubles: two
/// out-of-bounds length fields rather than one, and two credentials that can each be wrong on their own.
/// </para>
/// </remarks>
/// <param name="keys">The shared key material.</param>
[Collection(HybridKeyCollection.Name)]
public sealed class HybridFailureTests(HybridKeyFixture keys)
{
    private const MLKemParameterSet Default = MLKemParameterSet.MLKem1024;
    private const int DefaultN = HybridTestData.WrappedSecretLength2048;
    private const int DefaultM = MLKemTestData.EncapsulationLength1024;

    /// <summary>All four ciphers.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<Cipher> Ciphers() => [.. HybridTestData.AllCiphers];

    /// <summary>The three parameter sets.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<MLKemParameterSet> ParameterSets() => [.. HybridKeyFixture.AllParameterSets];

    /// <summary>
    /// Every named field of the hybrid header, by offset, for RSA-2048 and ML-KEM-1024 — so <c>N</c> = 256
    /// and <c>M</c> = 1,568.
    /// </summary>
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
        { "wrapped-secret length (first byte)", 18 },
        { "wrapped-secret length (last byte)", 21 },
        { "wrapped secret (first byte)", 22 },
        { "wrapped secret (middle byte)", 22 + (DefaultN / 2) },
        { "wrapped secret (last byte)", 22 + DefaultN - 1 },
        { "encapsulation length (first byte)", 22 + DefaultN },
        { "encapsulation length (last byte)", 25 + DefaultN },
        { "encapsulation (first byte)", 26 + DefaultN },
        { "encapsulation (middle byte)", 26 + DefaultN + (DefaultM / 2) },
        { "encapsulation (last byte)", 26 + DefaultN + DefaultM - 1 },
        { "key-confirmation tag (first byte)", 26 + DefaultN + DefaultM },
        { "key-confirmation tag (last byte)", HybridTestData.HeaderLength(DefaultN, DefaultM) - 1 },
    };

    // --- Both secrets contribute --------------------------------------------------------------------

    /// <summary>
    /// <b>Right RSA key, wrong ML-KEM key → refused, at key confirmation, before a payload byte is read.</b>
    /// </summary>
    /// <remarks>
    /// This is an isolation test for the ML-KEM secret and not merely a wrong-credential test. Implicit
    /// rejection means the decapsulation <i>succeeds</i>; the RSA half unwraps correctly; both ciphertexts are
    /// exactly as written, so the combiner's transcript is unchanged. The only thing that differs between the
    /// container's data key and the reader's is <c>kemSecret</c> — so if the combiner ignored it, this
    /// container would decrypt. The payload here is a stream that throws if it is read at all, which turns
    /// "before a single payload byte is read" (<c>docs/format.md</c> §6.2) from a claim into a test.
    /// </remarks>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task TheMLKemSecretContributesToTheDataKey(MLKemParameterSet parameterSet)
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), HybridTestData.Plaintext(8_192),
            Cipher.Aes256Gcm, parameterSet);

        using PoisonedPayloadStream input = new(container[..HybridTestData.HeaderLengthOf(parameterSet)]);
        using MemoryStream output = new();

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.Service().DecryptAsync(
                input, output, keys.RsaPrivateKeyPem, keys.UnrelatedMLKemPrivateKey(parameterSet),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("key-confirmation tag", exception.Message);
        Assert.False(input.PayloadWasRead);
        Assert.Equal(0, output.Length);
    }

    /// <summary>
    /// <b>The RSA secret contributes.</b> A hostile-sender container whose RSAES-OAEP ciphertext unwraps
    /// perfectly to a 32-byte secret, but whose key-confirmation tag was computed under a data key combined
    /// from a <i>different</i> RSA secret — with the transcript, and therefore everything the combiner binds
    /// to, byte-identical between the two.
    /// </summary>
    /// <remarks>
    /// This is the RSA-half analogue of <see cref="TheMLKemSecretContributesToTheDataKey"/>, and it exists
    /// because the obvious test — handing over the wrong RSA private key — proves less than it appears to:
    /// OAEP rejects that key before the combiner runs, so it would pass even if the RSA secret were dropped.
    /// Here nothing rejects anything until the combined key is checked.
    /// </remarks>
    [Fact]
    public async Task TheRsaSecretContributesToTheDataKey()
    {
        byte[] realSecret = FormatTestData.Sequence(0x00, DataEncryptionDefaults.DataKeySizeBytes);
        byte[] otherSecret = FormatTestData.Sequence(0xA0, DataEncryptionDefaults.DataKeySizeBytes);

        // The container transports realSecret...
        byte[] wrapped = HybridTestData.WrapOaep(realSecret, keys.RsaPublicKeyPem);
        (byte[] encapsulation, byte[] kemSecret) =
            HybridTestData.Encapsulate(keys.MLKemPublicKey(Default), Default);

        // ...but its tag is sealed under a data key combined from otherSecret. Same transcript, one secret
        // different.
        byte[] hostileDataKey = HybridTestData.Combine(otherSecret, kemSecret, wrapped, encapsulation);
        byte[] header = await HybridTestData.BuildHeaderAsync(
            Default, wrapped, encapsulation, hostileDataKey);

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.Service().DecryptAsync(
                input, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("key-confirmation tag", exception.Message);
        Assert.False(input.PayloadWasRead);

        // The premise: the ciphertext really does unwrap, so nothing before key confirmation could object.
        Assert.Equal(realSecret, HybridTestData.UnwrapOaep(wrapped, keys.RsaPrivateKeyPem));
        Assert.NotEqual(
            hostileDataKey, HybridTestData.Combine(realSecret, kemSecret, wrapped, encapsulation));
    }

    /// <summary>
    /// The same shape once more, with the ML-KEM secret substituted instead — the pair of hostile-sender
    /// containers together show the combiner is not merely a function of <i>one</i> secret and the
    /// transcript.
    /// </summary>
    [Fact]
    public async Task AHeaderSealedUnderAnotherKemSecretIsCaughtByKeyConfirmation()
    {
        byte[] rsaSecret = FormatTestData.Sequence(0x00, DataEncryptionDefaults.DataKeySizeBytes);
        byte[] wrapped = HybridTestData.WrapOaep(rsaSecret, keys.RsaPublicKeyPem);
        (byte[] encapsulation, byte[] kemSecret) =
            HybridTestData.Encapsulate(keys.MLKemPublicKey(Default), Default);

        byte[] otherKemSecret = FormatTestData.Sequence(0x5A, DataEncryptionDefaults.DataKeySizeBytes);
        byte[] header = await HybridTestData.BuildHeaderAsync(
            Default,
            wrapped,
            encapsulation,
            HybridTestData.Combine(rsaSecret, otherKemSecret, wrapped, encapsulation));

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.Service().DecryptAsync(
                input, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains("key-confirmation tag", exception.Message);
        Assert.False(input.PayloadWasRead);
        Assert.NotEqual(otherKemSecret, kemSecret);
    }

    /// <summary>
    /// <b>Wrong RSA key, right ML-KEM key → refused.</b> The plan's other named case. It fails at the OAEP
    /// unwrap rather than at key confirmation — earlier, and with Enigma.Core's diagnosis inside — which the
    /// assertions state explicitly so the difference from the ML-KEM half is on the record.
    /// </summary>
    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task TheWrongRsaPrivateKeyIsADecryptionError(Cipher cipher)
    {
        byte[] plaintext = HybridTestData.Plaintext(256);
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, cipher, Default);

        DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.UnrelatedRsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container));

        Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
        Assert.Contains("RSA private key", exception.Message);

        // …and the other way round, so neither key pair is special.
        byte[] unrelatedContainer = await HybridTestData.EncryptToBytesAsync(
            keys.UnrelatedRsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, cipher, Default);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), unrelatedContainer));
    }

    /// <summary>
    /// Neither half alone opens a container, stated as one test: the right RSA key with the wrong ML-KEM key
    /// fails, the wrong RSA key with the right ML-KEM key fails, and only the pair succeeds.
    /// </summary>
    [Fact]
    public async Task NeitherCredentialAloneOpensAContainer()
    {
        byte[] plaintext = HybridTestData.Plaintext(128);
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.UnrelatedMLKemPrivateKey(Default), container));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.UnrelatedRsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container));

        // Both wrong at once fails too, and it is the RSA unwrap that reports it — that half runs first
        // (docs/format.md §7.2 step 4).
        DataDecryptionException both = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.UnrelatedRsaPrivateKeyPem, keys.UnrelatedMLKemPrivateKey(Default), container));
        Assert.Contains("RSA private key", both.Message);

        // Only the pair opens it.
        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container));
    }

    /// <summary>The right pair does reach the payload — the poisoned stream is not why the tests above fail.</summary>
    [Fact]
    public async Task TheRightCredentialPairDoesReachThePayload()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        using PoisonedPayloadStream input = new(container[..HybridTestData.HeaderLengthOf(Default)]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<IOException>(
            () => HybridTestData.Service().DecryptAsync(
                input, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.True(input.PayloadWasRead);
    }

    // --- The credentials themselves -----------------------------------------------------------------

    /// <summary>
    /// An ML-KEM private key for a different parameter set, or of the wrong length, is a decryption error
    /// carrying Enigma.Core's own diagnosis — the same §9 rule the ML-KEM method applies, for the same
    /// reason.
    /// </summary>
    [Fact]
    public async Task AnUnusableMLKemPrivateKeyIsADecryptionErrorWithTheCauseInside()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);
        byte[] right = keys.MLKemPrivateKey(Default);

        foreach (byte[] key in new[]
                 {
                     new byte[1],
                     new byte[right.Length - 1],
                     new byte[right.Length + 1],
                     keys.MLKemPrivateKey(MLKemParameterSet.MLKem512),
                     keys.MLKemPrivateKey(MLKemParameterSet.MLKem768),
                 })
        {
            DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
                () => HybridTestData.DecryptToBytesAsync(keys.RsaPrivateKeyPem, key, container));

            Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
        }
    }

    /// <summary>
    /// An encrypted RSA PEM opened with the wrong passphrase, or with none, is a decryption error — the §9
    /// rule that an undecryptable PEM is not separable from a wrong key.
    /// </summary>
    [Fact]
    public async Task AnUndecryptableRsaPrivateKeyPemIsADecryptionErrorWithTheCauseInside()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.EncryptedPemRsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        DataDecryptionException wrongPassphrase = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.EncryptedRsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container,
                "not-the-passphrase".ToCharArray()));
        Assert.IsAssignableFrom<CryptographicException>(wrongPassphrase.InnerException);

        DataDecryptionException noPassphrase = await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.EncryptedRsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container));
        Assert.IsAssignableFrom<CryptographicException>(noPassphrase.InnerException);
    }

    /// <summary>
    /// An RSA PEM that cannot be <b>parsed</b> keeps its own identity and propagates untouched — the
    /// credential-supply versus file-content split of §9, which the hybrid inherits verbatim.
    /// </summary>
    /// <remarks>
    /// <b>Note which parameter name comes back.</b> Because the exception propagates unwrapped, the
    /// <c>ParamName</c> is Enigma.Core's <c>privateKeyPem</c> rather than this method's
    /// <c>rsaPrivateKeyPem</c>. The RSA service does not show that seam, since its own parameter happens to
    /// be named the same; the hybrid has to disambiguate its two keys, so the names diverge. Correcting it
    /// would mean catching and re-throwing, which is precisely the wrapping §9 rules out for this row — so
    /// the divergence is documented on the interface instead of papered over here.
    /// </remarks>
    [Fact]
    public async Task AnUnparseableRsaPrivateKeyPemPropagatesUnwrapped()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        // Base64 that is not Base64. Under Enigma.Core 1.0.0 (BouncyCastle 2.6.2) the platform decoder's
        // FormatException escaped raw; Enigma.Core 1.1.0 (BouncyCastle 2.7.0) has PemReader wrap it in an
        // IOException, which Enigma.Core maps to ArgumentException. Both are §9 outcomes — this pins which
        // one, so the next drift is a red test. The FormatException is still there, nested below.
        ArgumentException malformed = await Assert.ThrowsAsync<ArgumentException>(
            () => HybridTestData.DecryptToBytesAsync(
                RsaTestData.MalformedPem, keys.MLKemPrivateKey(Default), container));

        Assert.Equal("privateKeyPem", malformed.ParamName);
        Assert.NotNull(RsaTestData.FirstFormatException(malformed));

        foreach (string pem in new[] { RsaTestData.NotAPem, keys.RsaPublicKeyPem })
        {
            ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
                () => HybridTestData.DecryptToBytesAsync(pem, keys.MLKemPrivateKey(Default), container));

            Assert.Equal("privateKeyPem", exception.ParamName);
        }

        // A null or empty PEM is *this* library's to reject, and there the name is ours.
        Assert.Equal(
            "rsaPrivateKeyPem",
            (await Assert.ThrowsAsync<ArgumentException>(
                () => HybridTestData.DecryptToBytesAsync(
                    string.Empty, keys.MLKemPrivateKey(Default), container))).ParamName);
    }

    /// <summary>And the same distinction on the way out, for each of the two public keys in turn.</summary>
    [Fact]
    public async Task AnUnusablePublicKeyIsReportedAgainstTheKeyThatCausedIt()
    {
        byte[] plaintext = HybridTestData.Plaintext(64);

        // An unusable RSA public key is Enigma.Core's to reject, and it propagates unwrapped — so the name
        // is Enigma.Core's too. See AnUnparseableRsaPrivateKeyPemPropagatesUnwrapped.
        // Invalid Base64 became an ArgumentException in Enigma.Core 1.1.0 (BouncyCastle 2.7.0), where 1.0.0
        // (BouncyCastle 2.6.2) let a raw FormatException escape. §9 permits both; the name is Enigma.Core's
        // either way.
        ArgumentException malformed = await Assert.ThrowsAsync<ArgumentException>(
            () => HybridTestData.EncryptToBytesAsync(
                "-----BEGIN PUBLIC KEY-----\nnot base64!!\n-----END PUBLIC KEY-----\n",
                keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default));

        Assert.Equal("publicKeyPem", malformed.ParamName);
        Assert.NotNull(RsaTestData.FirstFormatException(malformed));

        ArgumentException rsa = await Assert.ThrowsAsync<ArgumentException>(
            () => HybridTestData.EncryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default));
        Assert.Equal("publicKeyPem", rsa.ParamName);

        // An unusable ML-KEM public key is an argument error naming *that* parameter — the encrypt side has
        // no ambiguity to resolve, because Encapsulate takes the key and nothing else (§9).
        byte[] rightKemKey = keys.MLKemPublicKey(Default);
        foreach (byte[] key in new[]
                 {
                     new byte[1],
                     new byte[rightKemKey.Length - 1],
                     new byte[rightKemKey.Length + 1],
                     keys.MLKemPublicKey(MLKemParameterSet.MLKem512),
                 })
        {
            ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
                () => HybridTestData.EncryptToBytesAsync(
                    keys.RsaPublicKeyPem, key, plaintext, Cipher.Aes256Gcm, Default));

            Assert.Equal("mlKemPublicKey", exception.ParamName);
            Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
        }
    }

    /// <summary>
    /// An unusable public key of either kind leaves the output stream untouched: both public-key operations
    /// precede the header, and therefore every write.
    /// </summary>
    [Fact]
    public async Task AnUnusablePublicKeyWritesNothing()
    {
        foreach ((string rsaPem, byte[] kemKey) in new[]
                 {
                     (RsaTestData.NotAPem, keys.MLKemPublicKey(Default)),
                     (keys.RsaPublicKeyPem, new byte[7]),
                 })
        {
            using MemoryStream input = new(HybridTestData.Plaintext(64), writable: false);
            using MemoryStream output = new();

            await Assert.ThrowsAnyAsync<ArgumentException>(
                () => HybridTestData.Service().EncryptAsync(
                    input, output, Cipher.Aes256Gcm, rsaPem, kemKey, Default, null,
                    TestContext.Current.CancellationToken));

            Assert.Equal(0, output.Length);
        }
    }

    /// <summary>
    /// A public key of the right length for another parameter set is refused under the one the caller named,
    /// so the parameter set and the ML-KEM key cannot silently disagree.
    /// </summary>
    [Fact]
    public async Task AnMLKemPublicKeyForAnotherParameterSetIsRefused()
    {
        byte[] plaintext = HybridTestData.Plaintext(64);

        foreach (MLKemParameterSet declared in HybridKeyFixture.AllParameterSets)
        {
            foreach (MLKemParameterSet actual in HybridKeyFixture.AllParameterSets)
            {
                if (declared == actual) continue;

                ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(
                    () => HybridTestData.EncryptToBytesAsync(
                        keys.RsaPublicKeyPem, keys.MLKemPublicKey(actual), plaintext, Cipher.Aes256Gcm,
                        declared));

                Assert.Equal("mlKemPublicKey", exception.ParamName);
            }
        }
    }

    // --- The hostile sender's wrapped secret --------------------------------------------------------

    /// <summary>
    /// A wrapped secret that unwraps to something that is not 32 bytes is a format error, caught before the
    /// combiner runs. Only a sender can produce this — it needs the recipient's public key — and without the
    /// length check the short "secret" would reach the combiner as an HMAC key of the wrong size.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public async Task AWrappedSecretThatIsNot32BytesIsAFormatError(int wrappedLength)
    {
        byte[] hostileSecret = FormatTestData.Sequence(0x70, wrappedLength);
        byte[] wrapped = HybridTestData.WrapOaep(hostileSecret, keys.RsaPublicKeyPem);
        (byte[] encapsulation, byte[] kemSecret) =
            HybridTestData.Encapsulate(keys.MLKemPublicKey(Default), Default);

        // The tag is beside the point: the length check runs before the combiner and before confirmation.
        byte[] header = await HybridTestData.BuildHeaderAsync(
            Default, wrapped, encapsulation,
            HybridTestData.Combine(
                FormatTestData.DataKey(), kemSecret, wrapped, encapsulation));

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.Service().DecryptAsync(
                input, output, keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Contains($"{wrappedLength} bytes", exception.Message);
        Assert.Contains("0x05", exception.Message);
        Assert.False(input.PayloadWasRead);
    }

    // --- A tampered payload -------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(Ciphers))]
    public async Task AFlippedPayloadBitIsADecryptionError(Cipher cipher)
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(256), cipher,
            Default);

        byte[] tampered = FormatTestData.WithFlippedBit(
            container, HybridTestData.HeaderLengthOf(Default) * 8);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), tampered));
    }

    /// <summary>Anywhere in the payload, including the GCM tag that closes it.</summary>
    [Fact]
    public async Task AFlippedBitAnywhereInThePayloadIsADecryptionError()
    {
        int headerLength = HybridTestData.HeaderLengthOf(Default);
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(200),
            Cipher.Aes256Gcm, Default);

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
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), tampered));
        }
    }

    [Fact]
    public async Task ATruncatedOrExtendedPayloadIsADecryptionError()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(200),
            Cipher.Aes256Gcm, Default);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container[..^8]));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default),
                container[..HybridTestData.HeaderLengthOf(Default)]));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), [.. container, 0x00]));
    }

    // --- An edited header ---------------------------------------------------------------------------

    /// <summary>
    /// Every named field of the header, edited in turn. The outcome is always one of the two documented
    /// exceptions: <see cref="DataEncryptionFormatException"/> where the edit makes the header structurally
    /// invalid, <see cref="DataDecryptionException"/> where it stays parseable and the OAEP unwrap, the
    /// decapsulation, the key-confirmation tag or the GCM AAD catches it.
    /// </summary>
    [Theory]
    [MemberData(nameof(HeaderFields))]
    public async Task EditingAnyHeaderFieldIsDetected(string field, int offset)
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(128),
            Cipher.Aes256Gcm, Default);
        byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

        DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), edited));

        Assert.True(
            exception is DataEncryptionFormatException or DataDecryptionException,
            $"Editing the {field} at offset {offset} raised {exception.GetType().Name}.");
    }

    /// <summary>
    /// And every byte of the header, not only the fields a hand-written list happens to name. ML-KEM-512 is
    /// used so the sweep is 1,066 cases rather than 1,866 — the shape is identical, only <c>M</c> differs.
    /// </summary>
    [Fact]
    public async Task EditingAnyHeaderByteIsDetected()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, parameterSet);

        for (int offset = 0; offset < HybridTestData.HeaderLengthOf(parameterSet); offset++)
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), edited));

            Assert.True(
                exception is DataEncryptionFormatException or DataDecryptionException,
                $"Flipping a bit at header offset {offset} raised {exception.GetType().Name}.");
        }
    }

    /// <summary>The structural fields are format errors specifically, not merely "some" error.</summary>
    [Fact]
    public async Task EditingTheMagicOrTheVersionIsAFormatError()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        foreach (int offset in new[] { 0, 1, 3 })
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), edited));
        }
    }

    /// <summary>
    /// Editing the cipher byte to <b>another valid cipher</b>: the header still parses and both ciphertexts
    /// are intact, so what catches it is the key-confirmation tag — the header is covered by it (§6).
    /// </summary>
    [Fact]
    public async Task EditingTheCipherByteToAnotherValidCipherIsADecryptionError()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        byte[] edited = FormatTestData.WithByteAt(container, 4, (byte)Cipher.Serpent256Gcm);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), edited));
    }

    [Fact]
    public async Task EditingTheCipherByteToAnUndefinedValueIsAFormatError()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        foreach (byte cipherByte in new byte[] { 0x00, 0x05, 0xFF })
        {
            byte[] edited = FormatTestData.WithByteAt(container, 4, cipherByte);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), edited));
        }
    }

    // --- The parameter-set byte ---------------------------------------------------------------------

    /// <summary>
    /// An undefined parameter-set byte is a format error raised <b>before either private key is touched</b>,
    /// which the poisoned factories prove. <c>0x00</c> matters most: the wire encoding is 1-based precisely
    /// so a zero-filled header cannot parse (§3.4).
    /// </summary>
    [Theory]
    [InlineData((byte)0x00)]
    [InlineData((byte)0x04)]
    [InlineData((byte)0x05)]
    [InlineData((byte)0x7F)]
    [InlineData((byte)0xFF)]
    public async Task AnUndefinedParameterSetByteIsAFormatErrorWithNoKeyWork(byte parameterSetByte)
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);
        byte[] edited = FormatTestData.WithByteAt(
            container, HybridTestData.ParameterSetOffset, parameterSetByte);

        DataEncryptionFormatException exception = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem,
                keys.MLKemPrivateKey(Default),
                edited,
                service: HybridTestData.Service(
                    publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory(),
                    mlKemServiceFactory: new PoisonedMLKemServiceFactory())));

        Assert.Contains("parameter-set byte", exception.Message);
    }

    /// <summary>
    /// The parameter-set byte edited to a <b>different valid value</b>. As for method <c>0x04</c>, the
    /// header still parses and both length fields still pass their bounds check — but the reader then builds
    /// a KEM for the parameter set the byte now claims and hands it a ciphertext and a key sized for the real
    /// one, so decapsulation cannot succeed. The RSA unwrap happens first and succeeds, so the failure is
    /// demonstrably the ML-KEM half's.
    /// </summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task EditingTheParameterSetByteToAnotherValidValueIsADecryptionError(
        MLKemParameterSet written)
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(written), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, written);

        foreach (MLKemParameterSet claimed in HybridKeyFixture.AllParameterSets)
        {
            if (claimed == written) continue;

            byte[] edited = FormatTestData.WithByteAt(
                container, HybridTestData.ParameterSetOffset, MLKemTestData.WireByteOf(claimed));

            DataDecryptionException exception = await Assert.ThrowsAsync<DataDecryptionException>(
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(written), edited));

            Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
            Assert.Contains("ML-KEM private key", exception.Message);
        }
    }

    // --- Method and stream shape --------------------------------------------------------------------

    /// <summary>
    /// Handing another method's container to the hybrid service is a format error, not a misparse — and the
    /// reverse holds too. The ML-KEM case is the pointed one: a hybrid header and an ML-KEM header agree on
    /// their first 18 bytes but for the method byte, so only that byte separates them.
    /// </summary>
    [Fact]
    public async Task AnotherMethodsContainerIsAFormatError()
    {
        byte[] plaintext = HybridTestData.Plaintext(64);
        byte[] hybridContainer = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);
        byte[] mlKemContainer = await MLKemTestData.EncryptToBytesAsync(
            keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);
        byte[] rsaContainer = await RsaTestData.EncryptToBytesAsync(keys.RsaPublicKeyPem, plaintext);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), mlKemContainer));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), rsaContainer));

        // And the two single-primitive services refuse the hybrid container.
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => MLKemTestData.DecryptToBytesAsync(keys.MLKemPrivateKey(Default), hybridContainer));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => RsaTestData.DecryptToBytesAsync(keys.RsaPrivateKeyPem, hybridContainer));
    }

    [Fact]
    public async Task AnEmptyOrTinyStreamIsAFormatError()
    {
        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), []));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), [0xEC]));
    }

    /// <summary>A header cut short anywhere is a format error, at every offset.</summary>
    [Fact]
    public async Task ATruncatedHeaderIsAFormatErrorAtEveryOffset()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, parameterSet);

        for (int length = 0; length < HybridTestData.HeaderLengthOf(parameterSet); length++)
        {
            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), container[..length]));
        }
    }

    // --- The two length fields ----------------------------------------------------------------------

    /// <summary>
    /// Both length fields at one over their cap, at zero, negative, and at both extremes of
    /// <see cref="int"/> — rejected as format errors with <b>no key work attempted at all</b>: the service
    /// is wired with poisoned RSA <i>and</i> ML-KEM factories that throw if either is reached.
    /// </summary>
    /// <remarks>
    /// This is what the limits are for (<c>docs/format.md</c> §8). <see cref="int.MaxValue"/> is the pointed
    /// case — a claim of 2 GiB, which must cost a comparison to reject rather than an allocation to survive
    /// — and the hybrid has two fields that can carry it rather than one.
    /// </remarks>
    [Fact]
    public async Task EitherLengthFieldOutOfBoundsIsAFormatErrorWithNoKeyWork()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);
        HybridDataEncryptionService reader = HybridTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory(),
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());

        int[] offsets =
        [
            HybridTestData.WrappedSecretLengthOffset,
            HybridTestData.EncapsulationLengthOffset(DefaultN),
        ];

        foreach (int offset in offsets)
        {
            foreach (int value in new[] { 4_097, 0, -1, int.MinValue, int.MaxValue })
            {
                byte[] edited = FormatTestData.WithInt32At(container, offset, value);

                await Assert.ThrowsAsync<DataEncryptionFormatException>(
                    () => HybridTestData.DecryptToBytesAsync(
                        keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), edited, service: reader));
            }
        }
    }

    /// <summary>Each zero-length field is named by the field name that rejected it, and they differ.</summary>
    [Fact]
    public async Task AZeroLengthFieldNamesTheRightField()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        DataEncryptionFormatException wrapped = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem,
                keys.MLKemPrivateKey(Default),
                FormatTestData.WithInt32At(container, HybridTestData.WrappedSecretLengthOffset, 0)));
        Assert.Contains("RSA wrapped-key length", wrapped.Message);

        DataEncryptionFormatException encapsulation = await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem,
                keys.MLKemPrivateKey(Default),
                FormatTestData.WithInt32At(
                    container, HybridTestData.EncapsulationLengthOffset(DefaultN), 0)));
        Assert.Contains("ML-KEM encapsulation length", encapsulation.Message);
    }

    /// <summary>
    /// A length within its cap but longer than the stream can satisfy: the stream ends inside the header,
    /// which is a format error too. Both fields, since either can announce it.
    /// </summary>
    [Fact]
    public async Task ALengthBeyondTheEndOfTheStreamIsAFormatError()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);

        foreach (int offset in new[]
                 {
                     HybridTestData.WrappedSecretLengthOffset,
                     HybridTestData.EncapsulationLengthOffset(DefaultN),
                 })
        {
            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem,
                    keys.MLKemPrivateKey(Default),
                    FormatTestData.WithInt32At(container, offset, 4_096)));
        }
    }

    /// <summary>
    /// Tightening <i>either</i> cap refuses an otherwise valid container, and refuses it before either
    /// private key is used — the hybrid honours both caps independently (§8).
    /// </summary>
    [Fact]
    public async Task TighteningEitherCapRejectsAnOtherwiseValidHeader()
    {
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), HybridTestData.Plaintext(64),
            Cipher.Aes256Gcm, Default);
        HybridDataEncryptionService reader = HybridTestData.Service(
            publicKeyServiceFactory: new PoisonedPublicKeyServiceFactory(),
            mlKemServiceFactory: new PoisonedMLKemServiceFactory());

        foreach (DataEncryptionLimits limits in new[]
                 {
                     new DataEncryptionLimits { MaxWrappedKeyLength = DefaultN - 1 },
                     new DataEncryptionLimits { MaxEncapsulationLength = DefaultM - 1 },
                 })
        {
            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container, limits: limits,
                    service: reader));
        }
    }

    /// <summary>Limits exactly at both lengths are legal — the caps include their own value.</summary>
    [Fact]
    public async Task LimitsExactlyAtBothLengthsAreAccepted()
    {
        byte[] plaintext = HybridTestData.Plaintext(64);
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(Default), plaintext, Cipher.Aes256Gcm, Default);

        DataEncryptionLimits atCap = new()
        {
            MaxWrappedKeyLength = DefaultN,
            MaxEncapsulationLength = DefaultM,
        };

        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(Default), container, limits: atCap));
    }

    /// <summary>And the default limits accept what the service itself writes, at every parameter set.</summary>
    [Theory]
    [MemberData(nameof(ParameterSets))]
    public async Task TheDefaultLimitsAcceptTheServicesOwnOutput(MLKemParameterSet parameterSet)
    {
        byte[] plaintext = HybridTestData.Plaintext(64);
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), plaintext, Cipher.Aes256Gcm,
            parameterSet);

        Assert.Equal(
            plaintext,
            await HybridTestData.DecryptToBytesAsync(
                keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), container,
                limits: DataEncryptionLimits.Default));
    }

    /// <summary>
    /// Nothing above ever surfaces an exception type the contract does not name — no
    /// <see cref="NullReferenceException"/>, no indexing failure, no unwrapped Enigma.Core exception.
    /// </summary>
    /// <remarks>
    /// The systematic sweep across all five methods lives in <see cref="MalformedContainerSweepTests"/>;
    /// this is the hybrid slice of it, kept here so a regression is caught in the suite that owns the
    /// method. Both credentials are valid throughout, so only container errors are admissible.
    /// </remarks>
    [Fact]
    public async Task NoCorruptionEverEscapesTheDocumentedExceptionTypes()
    {
        const MLKemParameterSet parameterSet = MLKemParameterSet.MLKem512;
        byte[] container = await HybridTestData.EncryptToBytesAsync(
            keys.RsaPublicKeyPem, keys.MLKemPublicKey(parameterSet), HybridTestData.Plaintext(32),
            Cipher.Aes256Gcm, parameterSet);

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
                await HybridTestData.DecryptToBytesAsync(
                    keys.RsaPrivateKeyPem, keys.MLKemPrivateKey(parameterSet), candidate);
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
