using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Enigma.DataEncryption.UnitTests.Internal;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The failure half of the two password methods: the wrong password, an edited header, a tampered
/// payload, and a header whose cost fields are out of bounds.
/// </summary>
/// <remarks>
/// <para>
/// Two properties here are about <b>when</b> the failure happens rather than merely that it does, and
/// they are the reason the format carries a key-confirmation tag at all (<c>docs/format.md</c> §6.3):
/// </para>
/// <list type="bullet">
///   <item><description>a wrong password fails before a single payload byte is read — proved with a payload stream that throws if touched;</description></item>
///   <item><description>an out-of-bounds cost field fails before any derivation — proved with a key-derivation factory that throws if used.</description></item>
/// </list>
/// </remarks>
public sealed class PasswordFailureTests
{
    /// <summary>Both methods.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<PasswordMethod> Methods() => [PasswordMethod.Pbkdf2, PasswordMethod.Argon2];

    /// <summary>Both methods against all four ciphers.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<PasswordMethod, Cipher> MethodsAndCiphers() =>
        PasswordRoundTripTests.MethodsAndCiphers();

    /// <summary>Every named header field of both methods, by offset.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<PasswordMethod, string, int> HeaderFields()
    {
        TheoryData<PasswordMethod, string, int> data = [];
        foreach (PasswordMethod method in new[] { PasswordMethod.Pbkdf2, PasswordMethod.Argon2 })
        {
            data.Add(method, "magic byte 0", 0);
            data.Add(method, "magic byte 1", 1);
            data.Add(method, "method", 2);
            data.Add(method, "format version", 3);
            data.Add(method, "cipher", 4);
            data.Add(method, "nonce (first byte)", 5);
            data.Add(method, "nonce (last byte)", 16);
            data.Add(method, "salt (first byte)", 17);
            data.Add(method, "salt (last byte)", 32);
            data.Add(method, "iterations", 33);

            if (method == PasswordMethod.Argon2)
            {
                data.Add(method, "degree of parallelism", 37);
                data.Add(method, "memory size in KiB", 41);
                data.Add(method, "key-confirmation tag (first byte)", 45);
                data.Add(method, "key-confirmation tag (last byte)", 60);
            }
            else
            {
                data.Add(method, "key-confirmation tag (first byte)", 37);
                data.Add(method, "key-confirmation tag (last byte)", 52);
            }
        }

        return data;
    }

    // --- The wrong password -------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task TheWrongPasswordIsADecryptionError(PasswordMethod method, Cipher cipher)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            adapter, PasswordTestData.Plaintext(256), cipher);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, container, PasswordTestData.WrongPasswordBytes()));
    }

    /// <summary>
    /// <b>The headline assertion of this phase.</b> A wrong password is rejected by the key-confirmation
    /// tag, which is computed from the header alone — so the payload is never touched. The container's
    /// payload here is a stream that throws if it is read at all, which turns "before a single payload
    /// byte is read" from a claim into a test.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheWrongPasswordFailsBeforeThePayloadIsRead(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(4_096));

        using PoisonedPayloadStream input = new(container[..adapter.HeaderLength]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => adapter.DecryptAsync(
                input, output, PasswordTestData.WrongPasswordBytes(),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(input.PayloadWasRead);
        Assert.Equal(0, output.Length);
    }

    /// <summary>The right password, by contrast, does read the payload — the stream double is not the reason above.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheRightPasswordDoesReachThePayload(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(64));

        using PoisonedPayloadStream input = new(container[..adapter.HeaderLength]);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<IOException>(
            () => adapter.DecryptAsync(
                input, output, PasswordTestData.PasswordBytes(),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.True(input.PayloadWasRead);
    }

    /// <summary>A one-bit difference in the password is enough — nothing here is a prefix comparison.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task APasswordDifferingByOneBitIsRejected(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(32));
        byte[] almost = FormatTestData.WithFlippedBit(PasswordTestData.PasswordBytes(), 0);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, container, almost));
    }

    /// <summary>A password that is a prefix of the right one is rejected too.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ATruncatedPasswordIsRejected(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(32));
        byte[] prefix = PasswordTestData.PasswordBytes()[..8];

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, container, prefix));
    }

    // --- A tampered payload -------------------------------------------------------------------------

    [Theory]
    [MemberData(nameof(MethodsAndCiphers))]
    public async Task AFlippedPayloadBitIsADecryptionError(PasswordMethod method, Cipher cipher)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            adapter, PasswordTestData.Plaintext(256), cipher);

        byte[] tampered = FormatTestData.WithFlippedBit(container, adapter.HeaderLength * 8);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, tampered));
    }

    /// <summary>Anywhere in the payload, including the GCM tag that closes it.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AFlippedBitAnywhereInThePayloadIsADecryptionError(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(200));

        foreach (int offset in new[]
                 {
                     adapter.HeaderLength,                 // first ciphertext byte
                     adapter.HeaderLength + 100,           // the middle of the ciphertext
                     container.Length - 17,                // last ciphertext byte
                     container.Length - 16,                // first byte of the GCM tag
                     container.Length - 1,                 // last byte of the GCM tag
                 })
        {
            byte[] tampered = FormatTestData.WithFlippedBit(container, offset * 8);

            await Assert.ThrowsAsync<DataDecryptionException>(
                () => PasswordTestData.DecryptToBytesAsync(adapter, tampered));
        }
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ATruncatedPayloadIsADecryptionError(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(200));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, container[..^8]));

        // Even the payload removed entirely: the GCM tag is gone, so authentication cannot succeed.
        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, container[..adapter.HeaderLength]));
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ExtraBytesAppendedToThePayloadAreADecryptionError(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(64));

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, [.. container, 0x00]));
    }

    // --- An edited header ---------------------------------------------------------------------------

    /// <summary>
    /// Every named field of both headers, edited in turn. The outcome is always one of the two documented
    /// exceptions: <see cref="DataEncryptionFormatException"/> where the edit makes the header
    /// structurally invalid, <see cref="DataDecryptionException"/> where it stays parseable and the
    /// key-confirmation tag or the GCM AAD catches it.
    /// </summary>
    [Theory]
    [MemberData(nameof(HeaderFields))]
    public async Task EditingAnyHeaderFieldIsDetected(PasswordMethod method, string field, int offset)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(128));
        byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

        DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, edited));

        Assert.True(
            exception is DataEncryptionFormatException or DataDecryptionException,
            $"Editing the {field} at offset {offset} raised {exception.GetType().Name}.");
    }

    /// <summary>
    /// And every byte of the header, not only the fields a hand-written list happens to name.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EditingAnyHeaderByteIsDetected(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(64));

        for (int offset = 0; offset < adapter.HeaderLength; offset++)
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            DataEncryptionException exception = await Assert.ThrowsAnyAsync<DataEncryptionException>(
                () => PasswordTestData.DecryptToBytesAsync(adapter, edited));

            Assert.True(
                exception is DataEncryptionFormatException or DataDecryptionException,
                $"Flipping a bit at header offset {offset} raised {exception.GetType().Name}.");
        }
    }

    /// <summary>The structural fields are format errors specifically, not merely "some" error.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EditingTheMagicOrTheVersionIsAFormatError(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(64));

        foreach (int offset in new[] { 0, 1, 3 })
        {
            byte[] edited = FormatTestData.WithFlippedBit(container, offset * 8);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => PasswordTestData.DecryptToBytesAsync(adapter, edited));
        }
    }

    /// <summary>
    /// Editing the cipher byte to <b>another valid cipher</b> is the interesting case: the header still
    /// parses, so what catches it is the key-confirmation tag — the header is covered by it (§6).
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EditingTheCipherByteToAnotherValidCipherIsADecryptionError(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            adapter, PasswordTestData.Plaintext(64), Cipher.Aes256Gcm);

        byte[] edited = FormatTestData.WithByteAt(container, 4, (byte)Cipher.Serpent256Gcm);

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, edited));
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task EditingTheCipherByteToAnUndefinedValueIsAFormatError(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(64));

        foreach (byte cipherByte in new byte[] { 0x00, 0x05, 0xFF })
        {
            byte[] edited = FormatTestData.WithByteAt(container, 4, cipherByte);

            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => PasswordTestData.DecryptToBytesAsync(adapter, edited));
        }
    }

    /// <summary>
    /// An edited salt is caught by key confirmation, so — like a wrong password — it costs nothing beyond
    /// the header. The salt is part of the message the tag is computed over.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnEditedSaltIsCaughtBeforeThePayloadIsRead(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(4_096));
        byte[] header = FormatTestData.WithFlippedBit(container[..adapter.HeaderLength], 17 * 8);

        using PoisonedPayloadStream input = new(header);
        using MemoryStream output = new();

        await Assert.ThrowsAsync<DataDecryptionException>(
            () => adapter.DecryptAsync(
                input, output, PasswordTestData.PasswordBytes(),
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.False(input.PayloadWasRead);
    }

    /// <summary>
    /// Handing one method's container to the other method's service is a format error, not a misparse —
    /// each service reads only its own method byte (<c>docs/format.md</c> §2.2).
    /// </summary>
    [Theory]
    [InlineData(PasswordMethod.Pbkdf2, PasswordMethod.Argon2)]
    [InlineData(PasswordMethod.Argon2, PasswordMethod.Pbkdf2)]
    public async Task AnotherMethodsContainerIsAFormatError(PasswordMethod written, PasswordMethod read)
    {
        byte[] container = await PasswordTestData.EncryptToBytesAsync(
            PasswordServiceAdapter.Create(written), PasswordTestData.Plaintext(64));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => PasswordTestData.DecryptToBytesAsync(PasswordServiceAdapter.Create(read), container));
    }

    [Theory]
    [MemberData(nameof(Methods))]
    public async Task AnEmptyOrTinyStreamIsAFormatError(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, []));

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, [0xEC]));
    }

    /// <summary>A header cut short anywhere is a format error, at every offset.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ATruncatedHeaderIsAFormatErrorAtEveryOffset(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(64));

        for (int length = 0; length < adapter.HeaderLength; length++)
        {
            await Assert.ThrowsAsync<DataEncryptionFormatException>(
                () => PasswordTestData.DecryptToBytesAsync(adapter, container[..length]));
        }
    }

    // --- Cost fields out of bounds ------------------------------------------------------------------

    /// <summary>
    /// Every cost field, at one over its cap, at zero, negative and <see cref="int.MaxValue"/> — rejected
    /// as a format error, and <b>with no derivation attempted</b>: the service is wired with a
    /// key-derivation factory that throws if it is ever reached.
    /// </summary>
    /// <remarks>
    /// This is what the limits are for (<c>docs/format.md</c> §8). The Argon2 memory field at
    /// <see cref="int.MaxValue"/> is the pointed case — 2 TiB, which must cost a comparison to reject
    /// rather than an allocation to survive.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ACostFieldOutOfBoundsIsAFormatErrorWithNoDerivation(PasswordMethod method)
    {
        PasswordServiceAdapter writer = PasswordServiceAdapter.Create(method);
        PasswordServiceAdapter reader = PasswordServiceAdapter.Create(method, poisonKdf: true);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(writer, PasswordTestData.Plaintext(64));

        foreach (PasswordServiceAdapter.CostField field in writer.CostFields)
        {
            foreach (int value in new[] { field.Cap + 1, 0, -1, int.MinValue, int.MaxValue })
            {
                byte[] edited = FormatTestData.WithInt32At(container, field.Offset, value);

                DataEncryptionFormatException exception =
                    await Assert.ThrowsAsync<DataEncryptionFormatException>(
                        () => PasswordTestData.DecryptToBytesAsync(reader, edited));

                Assert.Contains(field.Name, exception.Message);
            }
        }
    }

    /// <summary>
    /// A cost field at its cap is accepted by the bounds check — the cap itself is legal, so the failure
    /// that follows comes from key confirmation rather than from validation.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task ACostFieldAtItsCapPassesValidation(PasswordMethod method)
    {
        PasswordServiceAdapter writer = PasswordServiceAdapter.Create(method);
        PasswordServiceAdapter reader = PasswordServiceAdapter.Create(method, poisonKdf: true);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(writer, PasswordTestData.Plaintext(64));

        foreach (PasswordServiceAdapter.CostField field in writer.CostFields)
        {
            byte[] edited = FormatTestData.WithInt32At(container, field.Offset, field.Cap);

            // Validation let it through, so the derivation was attempted — which the poisoned factory
            // reports. That is the assertion: the cap is a boundary that includes its own value.
            await Assert.ThrowsAsync<KdfInvokedException>(
                () => PasswordTestData.DecryptToBytesAsync(reader, edited));
        }
    }

    /// <summary>
    /// Tightened limits are honoured: a container written with legal costs is refused by a reader whose
    /// bounds are stricter than the header's values.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TightenedLimitsRejectAnOtherwiseValidHeader(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(64));

        DataEncryptionLimits strict = new()
        {
            MaxPbkdf2Iterations = PasswordServiceAdapter.TestIterations - 1,
            MaxArgon2MemorySizeKb = PasswordServiceAdapter.TestArgon2MemorySizeKb - 1,
        };

        await Assert.ThrowsAsync<DataEncryptionFormatException>(
            () => PasswordTestData.DecryptToBytesAsync(adapter, container, limits: strict));
    }

    /// <summary>And the default limits accept what the services themselves write.</summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task TheDefaultLimitsAcceptTheServicesOwnOutput(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] plaintext = PasswordTestData.Plaintext(64);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, plaintext);

        Assert.Equal(
            plaintext,
            await PasswordTestData.DecryptToBytesAsync(adapter, container, limits: DataEncryptionLimits.Default));
    }

    /// <summary>
    /// Nothing above ever surfaces an exception type the contract does not name — no
    /// <see cref="System.NullReferenceException"/>, no indexing failure, no unwrapped Enigma.Core
    /// exception.
    /// </summary>
    /// <remarks>
    /// The systematic sweep across all four methods lives in PHASE05; this is the password-method slice of
    /// it, so a regression here is caught in the phase that introduced it.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task NoCorruptionEverEscapesTheDocumentedExceptionTypes(PasswordMethod method)
    {
        PasswordServiceAdapter adapter = PasswordServiceAdapter.Create(method);
        byte[] container = await PasswordTestData.EncryptToBytesAsync(adapter, PasswordTestData.Plaintext(96));

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
                await PasswordTestData.DecryptToBytesAsync(adapter, candidate);
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
