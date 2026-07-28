using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The fourteen file-path wrappers, against real files: that they round-trip, that they overwrite, and —
/// the one with consequences — that a failure leaves no output file behind.
/// </summary>
/// <remarks>
/// <para>
/// These have to touch the filesystem. <c>FileMode.Create</c>, <c>FileShare.Read</c> on the input and
/// "the partial output was deleted" are statements about files, and a stream double cannot stand in for
/// them. Each test gets its own <see cref="TempWorkspace"/>.
/// </para>
/// <para>
/// <b>The no-orphan guarantee is the reason this class exists.</b> A decrypt that fails halfway has
/// already written plaintext to disk; leaving it there would turn a wrong password into a partial
/// disclosure of the file it refused to decrypt. Every failure mode below therefore asserts the absence
/// of the output file, not merely the exception.
/// </para>
/// </remarks>
public sealed class DataEncryptionFileExtensionsTests
{
    /// <summary>The five methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<ContainerMethodKind> Methods() => [.. ContainerMethodHarness.All];

    /// <summary>Every method against every cipher.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<ContainerMethodKind, Cipher> MethodsAndCiphers()
    {
        TheoryData<ContainerMethodKind, Cipher> data = [];
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            foreach (Cipher cipher in ContainerMethodHarness.AllCiphers)
            {
                data.Add(kind, cipher);
            }
        }

        return data;
    }

    // --- Round-trip --------------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task AFileRoundTripsThroughTheWrappers(ContainerMethodKind kind, Cipher cipher)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(1_024);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await EncryptFileAsync(harness, plainPath, containerPath, cipher);
        await DecryptFileAsync(harness, containerPath, recoveredPath);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));

        // The container on disk is the real thing, header and payload both.
        Assert.Equal(
            harness.HeaderLength + plaintext.Length + (DataEncryptionDefaults.GcmMacSizeBits / 8),
            new FileInfo(containerPath).Length);
    }

    /// <summary>An empty input file is a valid payload, exactly as it is through the stream overloads.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnEmptyFileRoundTrips(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", []);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await EncryptFileAsync(harness, plainPath, containerPath);
        await DecryptFileAsync(harness, containerPath, recoveredPath);

        Assert.Empty(File.ReadAllBytes(recoveredPath));
    }

    /// <summary>
    /// The container a wrapper writes is byte-compatible with the stream overloads — the wrappers add file
    /// handling, not a second format.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AContainerWrittenToAFileDecryptsThroughTheStreamOverloads(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(300);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");

        await EncryptFileAsync(harness, plainPath, containerPath);

        byte[] recovered = await harness.DecryptToBytesAsync(File.ReadAllBytes(containerPath));

        Assert.Equal(plaintext, recovered);
    }

    /// <summary>And the reverse: a container the stream overloads produced is decrypted from a file.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AContainerWrittenByTheStreamOverloadsDecryptsFromAFile(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(300);
        byte[] container = await harness.EncryptToBytesAsync(plaintext);

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("container.enc", container);
        string recoveredPath = workspace.PathFor("recovered.bin");

        await DecryptFileAsync(harness, containerPath, recoveredPath);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));
    }

    /// <summary>
    /// The <c>char[]</c> password wrappers reach the same plaintext as the <c>byte[]</c> ones and leave the
    /// caller's array alone — the promise their XML docs make.
    /// </summary>
    [Theory]
    [InlineData(PasswordMethod.Pbkdf2)]
    [InlineData(PasswordMethod.Argon2)]
    public async Task ThePasswordCharOverloadsRoundTripWithoutMutatingTheCallersArray(PasswordMethod method)
    {
        byte[] plaintext = ContainerFixtures.Plaintext(200);
        char[] password = PasswordTestData.PasswordChars();
        char[] expected = PasswordTestData.PasswordChars();

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        if (method == PasswordMethod.Pbkdf2)
        {
            IPbkdf2DataEncryptionService service = new Pbkdf2DataEncryptionService(
                new BlockCipherServiceFactory(), new Pbkdf2ServiceFactory(), new HmacServiceFactory());

            await service.EncryptFileAsync(
                plainPath, containerPath, Cipher.Aes256Gcm, password,
                ContainerMethodHarness.Pbkdf2Iterations,
                cancellationToken: TestContext.Current.CancellationToken);
            await service.DecryptFileAsync(
                containerPath, recoveredPath, password,
                cancellationToken: TestContext.Current.CancellationToken);
        }
        else
        {
            IArgon2DataEncryptionService service = new Argon2DataEncryptionService(
                new BlockCipherServiceFactory(), new Argon2ServiceFactory(), new HmacServiceFactory());

            await service.EncryptFileAsync(
                plainPath, containerPath, Cipher.Aes256Gcm, password,
                ContainerMethodHarness.Argon2Iterations, ContainerMethodHarness.Argon2MemorySizeKb,
                ContainerMethodHarness.Argon2DegreeOfParallelism,
                cancellationToken: TestContext.Current.CancellationToken);
            await service.DecryptFileAsync(
                containerPath, recoveredPath, password,
                cancellationToken: TestContext.Current.CancellationToken);
        }

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));
        Assert.Equal(expected, password);
    }

    /// <summary>The RSA wrapper reads an encrypted private-key PEM when given its passphrase.</summary>
    [Fact]
    public async Task TheRsaWrapperAcceptsAnEncryptedPrivateKeyPem()
    {
        IRsaDataEncryptionService service = RsaTestData.Service();
        byte[] plaintext = ContainerFixtures.Plaintext(128);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await service.EncryptFileAsync(
            plainPath, containerPath, Cipher.Aes256Gcm, RsaTestData.GoldenPublicKeyPem(),
            cancellationToken: TestContext.Current.CancellationToken);
        await service.DecryptFileAsync(
            containerPath, recoveredPath, RsaTestData.GoldenEncryptedPrivateKeyPem(),
            RsaTestData.GoldenPemPassphraseChars(),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));
    }

    /// <summary>
    /// The RSA wrapper honours the OAEP hash it is given, records it in the header, and round-trips through
    /// a <c>DecryptFileAsync</c> that takes no hash of its own — the hash comes from the file.
    /// </summary>
    [Theory]
    [InlineData(RsaOaepHash.Sha256, 0x02)]
    [InlineData(RsaOaepHash.Sha384, 0x03)]
    [InlineData(RsaOaepHash.Sha512, 0x04)]
    public async Task TheRsaWrapperHonoursTheOaepHash(RsaOaepHash oaepHash, byte expectedWireByte)
    {
        IRsaDataEncryptionService service = RsaTestData.Service();
        byte[] plaintext = ContainerFixtures.Plaintext(200);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await service.EncryptFileAsync(
            plainPath, containerPath, Cipher.Aes256Gcm, RsaTestData.GoldenPublicKeyPem(), oaepHash,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(expectedWireByte, File.ReadAllBytes(containerPath)[RsaTestData.OaepHashOffset]);

        await service.DecryptFileAsync(
            containerPath, recoveredPath, RsaTestData.GoldenPrivateKeyPem(),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));
    }

    /// <summary>
    /// Omitting the argument selects SHA-256 — so a caller written before the parameter existed keeps
    /// producing the same containers.
    /// </summary>
    [Fact]
    public async Task TheRsaWrapperDefaultsToSha256()
    {
        IRsaDataEncryptionService service = RsaTestData.Service();

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", ContainerFixtures.Plaintext(64));
        string containerPath = workspace.PathFor("container.enc");

        await service.EncryptFileAsync(
            plainPath, containerPath, Cipher.Aes256Gcm, RsaTestData.GoldenPublicKeyPem(),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(0x02, File.ReadAllBytes(containerPath)[RsaTestData.OaepHashOffset]);
    }

    /// <summary>
    /// A wrap that fails because the key is too small for the hash still deletes the partial output — the
    /// cleanup path, reached through an <see cref="ArgumentException"/> raised inside the operation rather
    /// than by the extension's own validation.
    /// </summary>
    [Fact]
    public async Task ATooSmallKeyLeavesNoOutputFileBehind()
    {
        IRsaDataEncryptionService service = RsaTestData.Service();
        (string publicKeyPem, _) = new PublicKeyServiceFactory().CreatePublicKeyService()
            .GenerateRsaKeyPair(1024);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", ContainerFixtures.Plaintext(64));
        string containerPath = workspace.PathFor("container.enc");

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.EncryptFileAsync(
                plainPath, containerPath, Cipher.Aes256Gcm, publicKeyPem, RsaOaepHash.Sha512,
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(File.Exists(containerPath), "The partial output file survived a failed wrap.");
    }

    /// <summary>The ML-KEM wrapper honours the parameter set it is given, and records it in the header.</summary>
    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, "512")]
    [InlineData(MLKemParameterSet.MLKem1024, "1024")]
    public async Task TheMLKemWrapperHonoursTheParameterSet(MLKemParameterSet parameterSet, string slug)
    {
        IMLKemDataEncryptionService service = MLKemTestData.Service();
        byte[] plaintext = ContainerFixtures.Plaintext(64);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await service.EncryptFileAsync(
            plainPath, containerPath, Cipher.Aes256Gcm, MLKemTestData.GoldenPublicKey(slug), parameterSet,
            cancellationToken: TestContext.Current.CancellationToken);
        await service.DecryptFileAsync(
            containerPath, recoveredPath, MLKemTestData.GoldenPrivateKey(slug),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));

        byte[] container = File.ReadAllBytes(containerPath);
        Assert.Equal(MLKemTestData.WireByteOf(parameterSet), container[MLKemTestData.ParameterSetOffset]);
    }

    /// <summary>
    /// The hybrid wrapper honours the parameter set it is given, records it in the header, and needs
    /// <b>both</b> credentials on the way back — the only wrapper pair that takes two.
    /// </summary>
    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, "512")]
    [InlineData(MLKemParameterSet.MLKem1024, "1024")]
    public async Task TheHybridWrapperHonoursTheParameterSetAndNeedsBothKeys(
        MLKemParameterSet parameterSet,
        string slug)
    {
        IHybridDataEncryptionService service = HybridTestData.Service();
        byte[] plaintext = ContainerFixtures.Plaintext(64);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await service.EncryptFileAsync(
            plainPath, containerPath, Cipher.Aes256Gcm, RsaTestData.GoldenPublicKeyPem(),
            MLKemTestData.GoldenPublicKey(slug), parameterSet,
            cancellationToken: TestContext.Current.CancellationToken);
        await service.DecryptFileAsync(
            containerPath, recoveredPath, RsaTestData.GoldenPrivateKeyPem(),
            MLKemTestData.GoldenPrivateKey(slug),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));

        byte[] container = File.ReadAllBytes(containerPath);
        Assert.Equal(
            MLKemTestData.WireByteOf(parameterSet), container[HybridTestData.ParameterSetOffset]);

        // An encrypted RSA PEM works through the wrapper too, given its passphrase.
        string viaEncryptedPem = workspace.PathFor("via-encrypted-pem.bin");
        await service.DecryptFileAsync(
            containerPath, viaEncryptedPem, RsaTestData.GoldenEncryptedPrivateKeyPem(),
            MLKemTestData.GoldenPrivateKey(slug), RsaTestData.GoldenPemPassphraseChars(),
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(plaintext, File.ReadAllBytes(viaEncryptedPem));
    }

    // --- Overwrite semantics -----------------------------------------------------------------------

    /// <summary>
    /// <c>FileMode.Create</c>: an existing output file is replaced, not appended to and not refused. The
    /// pre-existing content is deliberately longer than the result, so a file merely written over would
    /// leave a recognisable tail behind.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnExistingOutputFileIsOverwrittenOnEncrypt(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(64);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.WriteFile("container.enc", new byte[8_192]);

        await EncryptFileAsync(harness, plainPath, containerPath);

        Assert.Equal(
            harness.HeaderLength + plaintext.Length + (DataEncryptionDefaults.GcmMacSizeBits / 8),
            new FileInfo(containerPath).Length);
        Assert.Equal(plaintext, await harness.DecryptToBytesAsync(File.ReadAllBytes(containerPath)));
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnExistingOutputFileIsOverwrittenOnDecrypt(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(64);
        byte[] container = await harness.EncryptToBytesAsync(plaintext);

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("container.enc", container);
        string recoveredPath = workspace.WriteFile("recovered.bin", new byte[8_192]);

        await DecryptFileAsync(harness, containerPath, recoveredPath);

        Assert.Equal(plaintext, File.ReadAllBytes(recoveredPath));
    }

    // --- No orphaned output ------------------------------------------------------------------------

    /// <summary>
    /// The headline guarantee: a wrong credential leaves nothing on disk. Not an empty file, not a partial
    /// plaintext — nothing.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AFailedDecryptLeavesNoOutputFile(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] container = await harness.EncryptToBytesAsync(ContainerFixtures.Plaintext(4_096));

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("container.enc", container);
        string recoveredPath = workspace.PathFor("recovered.bin");

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => harness.DecryptFileWithWrongCredentialAsync(containerPath, recoveredPath));

        Assert.False(File.Exists(recoveredPath), "The failed decrypt left an output file behind.");
    }

    /// <summary>
    /// And it removes a file that was already there. Overwrite-then-fail is the dangerous ordering: the
    /// caller's previous file is gone either way, so leaving a truncated replacement would be the worst of
    /// both.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AFailedDecryptRemovesAPreExistingOutputFile(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] container = await harness.EncryptToBytesAsync(ContainerFixtures.Plaintext(512));

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("container.enc", container);
        string recoveredPath = workspace.WriteFile("recovered.bin", new byte[64]);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => harness.DecryptFileWithWrongCredentialAsync(containerPath, recoveredPath));

        Assert.False(File.Exists(recoveredPath));
    }

    /// <summary>
    /// A tampered payload fails at the very end of the stream — after plaintext has already been written to
    /// the output file, which is precisely why the cleanup exists.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ATamperedPayloadLeavesNoOutputFile(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] container = await harness.EncryptToBytesAsync(ContainerFixtures.Plaintext(8_192));

        // The last byte of the GCM tag: authentication cannot fail any later than this.
        container[^1] ^= 0x01;

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("container.enc", container);
        string recoveredPath = workspace.PathFor("recovered.bin");

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => DecryptFileAsync(harness, containerPath, recoveredPath));

        Assert.False(File.Exists(recoveredPath));
    }

    /// <summary>A file that is not a container at all fails as a format error, and cleans up too.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ANonContainerInputLeavesNoOutputFile(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("not-a-container.enc", ContainerFixtures.Plaintext(200));
        string recoveredPath = workspace.PathFor("recovered.bin");

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => DecryptFileAsync(harness, containerPath, recoveredPath));

        Assert.False(File.Exists(recoveredPath));
    }

    /// <summary>Cancellation is a failure like any other, and the plan calls it out by name.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ACancelledOperationLeavesNoOutputFile(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", ContainerFixtures.Plaintext(512));
        string containerPath = workspace.PathFor("container.enc");

        using CancellationTokenSource cancelled = new();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => harness.EncryptFileAsync(plainPath, containerPath, Cipher.Aes256Gcm, null, cancelled.Token));

        Assert.False(File.Exists(containerPath));
    }

    /// <summary>
    /// A missing input file fails before any output exists — and must not delete an unrelated file that
    /// happens to sit at <c>outputPath</c>. The cleanup exists to remove what the operation itself wrote,
    /// not to reach for a file it never opened.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AMissingInputFileLeavesAPreExistingOutputFileAlone(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] bystander = [1, 2, 3, 4];

        using TempWorkspace workspace = new();
        string missingPath = workspace.PathFor("does-not-exist.bin");
        string outputPath = workspace.WriteFile("bystander.bin", bystander);

        await Assert.ThrowsAnyAsync<IOException>(
            () => EncryptFileAsync(harness, missingPath, outputPath));

        Assert.True(File.Exists(outputPath));
        Assert.Equal(bystander, File.ReadAllBytes(outputPath));
    }

    /// <summary>
    /// When the cleanup delete itself fails, the <i>original</i> exception is what propagates. The delete is
    /// best-effort by contract, and "could not delete the partial output" would replace the real reason the
    /// operation failed with a symptom of the attempt to tidy up after it.
    /// </summary>
    /// <remarks>
    /// Forcing a delete to fail means taking write permission off the containing directory, which only Unix
    /// file modes let a test do reliably — a Windows equivalent would need a second process or a share-mode
    /// trick, and would prove the same thing. The permission is removed from inside a progress callback, so
    /// it happens while the output file exists and its handle is still open; an already-open handle is
    /// unaffected by the directory's mode, so the write still completes and only the delete is blocked.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ADeleteFailureDoesNotMaskTheOriginalException(ContainerMethodKind kind)
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Unix file modes are how this test blocks the delete; Windows needs another lever.");
            return;
        }

        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] container = await harness.EncryptToBytesAsync(ContainerFixtures.Plaintext(64_000));
        container[^1] ^= 0x01;

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("container.enc", container);
        string outputDirectory = workspace.PathFor("locked");
        Directory.CreateDirectory(outputDirectory);
        string recoveredPath = Path.Combine(outputDirectory, "recovered.bin");

        UnixFileMode original = File.GetUnixFileMode(outputDirectory);

        // The guard is repeated inside the callback because the platform analyzer reasons per method body
        // and cannot see the early return above from within a lambda.
        IProgress<int> lockTheDirectory = new SynchronousProgress(_ =>
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(outputDirectory, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            }
        });

        try
        {
            // The tampered payload fails authentication; the cleanup then cannot remove the file.
            await Assert.ThrowsAsync<DataDecryptionException>(
                () => harness.DecryptFileAsync(
                    containerPath, recoveredPath, lockTheDirectory, TestContext.Current.CancellationToken));

            // The delete really was blocked — so the swallowed failure was exercised, not merely hoped for.
            Assert.True(File.Exists(recoveredPath));
        }
        finally
        {
            File.SetUnixFileMode(outputDirectory, original);
        }
    }

    /// <summary>
    /// An <see cref="IProgress{T}"/> that runs its callback inline on the reporting thread, so a test can act
    /// at a chosen point <i>during</i> an operation rather than after it.
    /// </summary>
    /// <param name="onReport">What to do on each report.</param>
    private sealed class SynchronousProgress(Action<int> onReport) : IProgress<int>
    {
        public void Report(int value) => onReport(value);
    }

    // --- Arguments ---------------------------------------------------------------------------------

    /// <summary>
    /// A rejected argument never touches the filesystem. Since the output is opened
    /// <c>FileMode.Create</c>, validating after opening would truncate the caller's existing file only to
    /// delete it again — so the validation runs first, and this is the test that says so.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnEmptyCredentialIsRejectedWithoutTouchingEitherFile(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] container = await harness.EncryptToBytesAsync(ContainerFixtures.Plaintext(64));
        byte[] existing = [9, 9, 9];

        using TempWorkspace workspace = new();
        string containerPath = workspace.WriteFile("container.enc", container);
        string existingPath = workspace.WriteFile("recovered.bin", existing);

        await Assert.ThrowsAnyAsync<ArgumentException>(
            () => harness.DecryptFileWithEmptyCredentialAsync(containerPath, existingPath));

        // Neither created nor truncated.
        Assert.Equal(existing, File.ReadAllBytes(existingPath));
    }

    /// <summary>
    /// Every wrapper rejects a null receiver — and does so <b>synchronously</b>, the convention the stream
    /// overloads follow, so an argument mistake faults the call rather than the returned task.
    /// </summary>
    [Fact]
    public void EveryWrapperRejectsANullReceiverSynchronously()
    {
        foreach (Func<Task> invocation in NullReceiverInvocations())
        {
            Assert.Throws<ArgumentNullException>(() => { _ = invocation(); });
        }
    }

    [Fact]
    public void EveryWrapperRejectsNullAndEmptyPathsSynchronously()
    {
        foreach (Func<string, string, Task> invocation in PathInvocations())
        {
            Assert.Equal(
                "inputPath",
                Assert.Throws<ArgumentNullException>(() => { _ = invocation(null!, "out"); }).ParamName);
            Assert.Equal(
                "outputPath",
                Assert.Throws<ArgumentNullException>(() => { _ = invocation("in", null!); }).ParamName);
            Assert.Equal(
                "inputPath",
                Assert.Throws<ArgumentException>(() => { _ = invocation(string.Empty, "out"); }).ParamName);
            Assert.Equal(
                "outputPath",
                Assert.Throws<ArgumentException>(() => { _ = invocation("in", string.Empty); }).ParamName);
        }
    }

    [Fact]
    public void TheEncryptWrappersRejectAnUndefinedCipher()
    {
        IPbkdf2DataEncryptionService pbkdf2 = new Pbkdf2DataEncryptionService();
        IArgon2DataEncryptionService argon2 = new Argon2DataEncryptionService();
        IRsaDataEncryptionService rsa = new RsaDataEncryptionService();
        IMLKemDataEncryptionService kem = new MLKemDataEncryptionService();
        IHybridDataEncryptionService hybrid = new HybridDataEncryptionService();
        const Cipher undefined = (Cipher)0x7F;
        byte[] password = PasswordTestData.PasswordBytes();

        Assert.Equal(
            "cipher",
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = pbkdf2.EncryptFileAsync("in", "out", undefined, password,
                    cancellationToken: CancellationToken.None);
            }).ParamName);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = argon2.EncryptFileAsync("in", "out", undefined, password,
                cancellationToken: CancellationToken.None);
        });

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = rsa.EncryptFileAsync("in", "out", undefined, RsaTestData.GoldenPublicKeyPem(),
                cancellationToken: CancellationToken.None);
        });

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = kem.EncryptFileAsync("in", "out", undefined, MLKemTestData.GoldenPublicKey("512"),
                cancellationToken: CancellationToken.None);
        });

        Assert.Throws<ArgumentOutOfRangeException>(() =>
        {
            _ = hybrid.EncryptFileAsync("in", "out", undefined, RsaTestData.GoldenPublicKeyPem(),
                MLKemTestData.GoldenPublicKey("512"), cancellationToken: CancellationToken.None);
        });
    }

    /// <summary>
    /// The cost parameters are bounded by the wrappers too. The stream overloads reject a non-positive cost
    /// with <see cref="ArgumentOutOfRangeException"/>; a wrapper that only forwarded would have opened —
    /// and so truncated — the output file first.
    /// </summary>
    [Fact]
    public void TheCostParametersAreBoundedByTheWrappersToo()
    {
        IPbkdf2DataEncryptionService pbkdf2 = new Pbkdf2DataEncryptionService();
        IArgon2DataEncryptionService argon2 = new Argon2DataEncryptionService();
        byte[] password = PasswordTestData.PasswordBytes();

        Assert.Equal(
            "iterations",
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = pbkdf2.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, password, 0,
                    cancellationToken: CancellationToken.None);
            }).ParamName);

        Assert.Equal(
            "iterations",
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = argon2.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, password, 0, 1_024, 1,
                    cancellationToken: CancellationToken.None);
            }).ParamName);

        Assert.Equal(
            "memorySizeKb",
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = argon2.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, password, 1, 0, 1,
                    cancellationToken: CancellationToken.None);
            }).ParamName);

        Assert.Equal(
            "degreeOfParallelism",
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = argon2.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, password, 1, 1_024, 0,
                    cancellationToken: CancellationToken.None);
            }).ParamName);
    }

    [Fact]
    public void TheMLKemWrapperRejectsAnUndefinedParameterSet()
    {
        IMLKemDataEncryptionService kem = new MLKemDataEncryptionService();

        Assert.Equal(
            "parameterSet",
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = kem.EncryptFileAsync(
                    "in", "out", Cipher.Aes256Gcm, MLKemTestData.GoldenPublicKey("512"),
                    (MLKemParameterSet)0x40, cancellationToken: CancellationToken.None);
            }).ParamName);
    }

    [Fact]
    public void TheHybridWrapperRejectsAnUndefinedParameterSet()
    {
        IHybridDataEncryptionService hybrid = new HybridDataEncryptionService();

        Assert.Equal(
            "parameterSet",
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                _ = hybrid.EncryptFileAsync(
                    "in", "out", Cipher.Aes256Gcm, RsaTestData.GoldenPublicKeyPem(),
                    MLKemTestData.GoldenPublicKey("512"), (MLKemParameterSet)0x40,
                    cancellationToken: CancellationToken.None);
            }).ParamName);
    }

    /// <summary>
    /// The hybrid wrapper validates <b>both</b> credentials before either file is opened, and names whichever
    /// one is at fault — the only wrapper pair where a caller can get one of two keys wrong.
    /// </summary>
    [Fact]
    public void TheHybridWrapperRejectsEitherEmptyCredential()
    {
        IHybridDataEncryptionService hybrid = new HybridDataEncryptionService();
        byte[] kemKey = MLKemTestData.GoldenPublicKey("512");
        string rsaPem = RsaTestData.GoldenPublicKeyPem();

        Assert.Equal(
            "rsaPublicKeyPem",
            Assert.Throws<ArgumentException>(() =>
            {
                _ = hybrid.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, string.Empty, kemKey,
                    cancellationToken: CancellationToken.None);
            }).ParamName);

        Assert.Equal(
            "mlKemPublicKey",
            Assert.Throws<ArgumentException>(() =>
            {
                _ = hybrid.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, rsaPem, [],
                    cancellationToken: CancellationToken.None);
            }).ParamName);

        Assert.Equal(
            "rsaPrivateKeyPem",
            Assert.Throws<ArgumentException>(() =>
            {
                _ = hybrid.DecryptFileAsync("in", "out", string.Empty,
                    MLKemTestData.GoldenPrivateKey("512"), cancellationToken: CancellationToken.None);
            }).ParamName);

        Assert.Equal(
            "mlKemPrivateKey",
            Assert.Throws<ArgumentException>(() =>
            {
                _ = hybrid.DecryptFileAsync("in", "out", RsaTestData.GoldenPrivateKeyPem(), [],
                    cancellationToken: CancellationToken.None);
            }).ParamName);
    }

    // --- Progress ----------------------------------------------------------------------------------

    /// <summary>
    /// Progress passes through the wrappers untouched: the reported increments sum to the payload byte
    /// count, and the header's bytes are not among them.
    /// </summary>
    /// <remarks>
    /// Enigma.Core reports <b>increments</b> — the size of each chunk it processed — rather than a running
    /// total, which is why the assertion is on <see cref="ProgressCollector.Total"/>. The collector records
    /// synchronously on the reporting thread; <see cref="Progress{T}"/> would post its callbacks through a
    /// synchronization context and race the assertion against the last report.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ProgressCountsPayloadBytesOnly(ContainerMethodKind kind)
    {
        ContainerMethodHarness harness = ContainerMethodHarness.For(kind);
        byte[] plaintext = ContainerFixtures.Plaintext(20_000);
        ProgressCollector encryptProgress = new();
        ProgressCollector decryptProgress = new();

        using TempWorkspace workspace = new();
        string plainPath = workspace.WriteFile("plain.bin", plaintext);
        string containerPath = workspace.PathFor("container.enc");
        string recoveredPath = workspace.PathFor("recovered.bin");

        await harness.EncryptFileAsync(
            plainPath, containerPath, Cipher.Aes256Gcm, encryptProgress,
            TestContext.Current.CancellationToken);
        await harness.DecryptFileAsync(
            containerPath, recoveredPath, decryptProgress, TestContext.Current.CancellationToken);

        // Exactly the payload: not one header byte more, in either direction.
        Assert.Equal(plaintext.Length, encryptProgress.Total);
        Assert.Equal(plaintext.Length, decryptProgress.Total);
        Assert.NotEmpty(encryptProgress.Values);
        Assert.NotEmpty(decryptProgress.Values);
        Assert.All(encryptProgress.Values, value => Assert.True(value > 0, "A progress increment was not positive."));
    }

    // --- Helpers -----------------------------------------------------------------------------------

    private static Task EncryptFileAsync(
        ContainerMethodHarness harness,
        string inputPath,
        string outputPath,
        Cipher cipher = Cipher.Aes256Gcm) =>
        harness.EncryptFileAsync(
            inputPath, outputPath, cipher, null, TestContext.Current.CancellationToken);

    private static Task DecryptFileAsync(
        ContainerMethodHarness harness,
        string inputPath,
        string outputPath) =>
        harness.DecryptFileAsync(inputPath, outputPath, null, TestContext.Current.CancellationToken);

    // --- The invocation tables ---------------------------------------------------------------------

    /// <summary>All fourteen wrappers, invoked with a null receiver.</summary>
    /// <returns>One thunk per wrapper.</returns>
    private static IEnumerable<Func<Task>> NullReceiverInvocations()
    {
        IPbkdf2DataEncryptionService? pbkdf2 = null;
        IArgon2DataEncryptionService? argon2 = null;
        IRsaDataEncryptionService? rsa = null;
        IMLKemDataEncryptionService? kem = null;
        IHybridDataEncryptionService? hybrid = null;

        byte[] password = PasswordTestData.PasswordBytes();
        char[] passwordChars = PasswordTestData.PasswordChars();
        string publicKeyPem = RsaTestData.GoldenPublicKeyPem();
        string privateKeyPem = RsaTestData.GoldenPrivateKeyPem();
        byte[] kemPublicKey = MLKemTestData.GoldenPublicKey("512");
        byte[] kemPrivateKey = MLKemTestData.GoldenPrivateKey("512");
        CancellationToken none = CancellationToken.None;

        yield return () => pbkdf2!.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, password, cancellationToken: none);
        yield return () => pbkdf2!.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, passwordChars, cancellationToken: none);
        yield return () => pbkdf2!.DecryptFileAsync("in", "out", password, cancellationToken: none);
        yield return () => pbkdf2!.DecryptFileAsync("in", "out", passwordChars, cancellationToken: none);
        yield return () => argon2!.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, password, cancellationToken: none);
        yield return () => argon2!.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, passwordChars, cancellationToken: none);
        yield return () => argon2!.DecryptFileAsync("in", "out", password, cancellationToken: none);
        yield return () => argon2!.DecryptFileAsync("in", "out", passwordChars, cancellationToken: none);
        yield return () => rsa!.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, publicKeyPem, cancellationToken: none);
        yield return () => rsa!.DecryptFileAsync("in", "out", privateKeyPem, cancellationToken: none);
        yield return () => kem!.EncryptFileAsync("in", "out", Cipher.Aes256Gcm, kemPublicKey, cancellationToken: none);
        yield return () => kem!.DecryptFileAsync("in", "out", kemPrivateKey, cancellationToken: none);
        yield return () => hybrid!.EncryptFileAsync(
            "in", "out", Cipher.Aes256Gcm, publicKeyPem, kemPublicKey, cancellationToken: none);
        yield return () => hybrid!.DecryptFileAsync(
            "in", "out", privateKeyPem, kemPrivateKey, cancellationToken: none);
    }

    /// <summary>All fourteen wrappers, parameterised by the two paths.</summary>
    /// <returns>One thunk per wrapper.</returns>
    private static IEnumerable<Func<string, string, Task>> PathInvocations()
    {
        IPbkdf2DataEncryptionService pbkdf2 = new Pbkdf2DataEncryptionService();
        IArgon2DataEncryptionService argon2 = new Argon2DataEncryptionService();
        IRsaDataEncryptionService rsa = new RsaDataEncryptionService();
        IMLKemDataEncryptionService kem = new MLKemDataEncryptionService();
        IHybridDataEncryptionService hybrid = new HybridDataEncryptionService();

        byte[] password = PasswordTestData.PasswordBytes();
        char[] passwordChars = PasswordTestData.PasswordChars();
        string publicKeyPem = RsaTestData.GoldenPublicKeyPem();
        string privateKeyPem = RsaTestData.GoldenPrivateKeyPem();
        byte[] kemPublicKey = MLKemTestData.GoldenPublicKey("512");
        byte[] kemPrivateKey = MLKemTestData.GoldenPrivateKey("512");
        CancellationToken none = CancellationToken.None;

        yield return (i, o) => pbkdf2.EncryptFileAsync(i, o, Cipher.Aes256Gcm, password, cancellationToken: none);
        yield return (i, o) => pbkdf2.EncryptFileAsync(i, o, Cipher.Aes256Gcm, passwordChars, cancellationToken: none);
        yield return (i, o) => pbkdf2.DecryptFileAsync(i, o, password, cancellationToken: none);
        yield return (i, o) => pbkdf2.DecryptFileAsync(i, o, passwordChars, cancellationToken: none);
        yield return (i, o) => argon2.EncryptFileAsync(i, o, Cipher.Aes256Gcm, password, cancellationToken: none);
        yield return (i, o) => argon2.EncryptFileAsync(i, o, Cipher.Aes256Gcm, passwordChars, cancellationToken: none);
        yield return (i, o) => argon2.DecryptFileAsync(i, o, password, cancellationToken: none);
        yield return (i, o) => argon2.DecryptFileAsync(i, o, passwordChars, cancellationToken: none);
        yield return (i, o) => rsa.EncryptFileAsync(i, o, Cipher.Aes256Gcm, publicKeyPem, cancellationToken: none);
        yield return (i, o) => rsa.DecryptFileAsync(i, o, privateKeyPem, cancellationToken: none);
        yield return (i, o) => kem.EncryptFileAsync(i, o, Cipher.Aes256Gcm, kemPublicKey, cancellationToken: none);
        yield return (i, o) => kem.DecryptFileAsync(i, o, kemPrivateKey, cancellationToken: none);
        yield return (i, o) => hybrid.EncryptFileAsync(
            i, o, Cipher.Aes256Gcm, publicKeyPem, kemPublicKey, cancellationToken: none);
        yield return (i, o) => hybrid.DecryptFileAsync(
            i, o, privateKeyPem, kemPrivateKey, cancellationToken: none);
    }
}
