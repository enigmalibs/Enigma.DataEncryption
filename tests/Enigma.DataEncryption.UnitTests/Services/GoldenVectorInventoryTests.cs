using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// The single inventory of every committed fixture: what each file is, which method, cipher, parameter set
/// and credential it belongs to, and what it must decrypt to.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this class exists.</b> Twenty committed binary files accumulated across PHASE02–PHASE04, each
/// intelligible only from the suite that happens to load it. A year from now, "what is
/// <c>mlkem-512-secret.bin</c> and may I delete it?" needs an answer that does not depend on reading four
/// test classes. The table below <i>is</i> that answer, and it is executable: every row decrypts its
/// container with its credential and compares against its expected plaintext, so a description that drifts
/// from the file it describes fails here rather than misleading someone later.
/// </para>
/// <para>
/// It deliberately duplicates coverage the per-method golden-vector suites already have. Those pin the
/// bytes; this one pins the <i>inventory</i> — that every fixture is accounted for, that none is orphaned,
/// and that no container fixture can be swapped for another method's without being noticed.
/// </para>
/// </remarks>
public sealed class GoldenVectorInventoryTests
{
    /// <summary>
    /// The complete inventory. Every file under <c>Services/Fixtures</c> appears exactly once, and
    /// <see cref="EveryCommittedFixtureIsInTheInventory"/> enforces that.
    /// </summary>
    /// <returns>The inventory rows.</returns>
    public static IReadOnlyList<FixtureRecord> Inventory() =>
    [
        // --- The shared plaintext ------------------------------------------------------------------
        new("golden-plaintext.txt", FixtureRole.ExpectedPlaintext,
            "The 45-byte plaintext every golden container in every method encrypts."),

        // --- Method 0x01 — PBKDF2 ------------------------------------------------------------------
        new("pbkdf2-aes.bin", FixtureRole.Container,
            "PBKDF2 · AES-256-GCM · password 'correct horse battery staple' · salt 10–1F · nonce 00–0B · "
            + "100,000 iterations. Data key and kcTag computed with Python's hashlib/hmac; payload with the "
            + "platform's AesGcm — independent of this library.",
            ContainerMethodKind.Pbkdf2),
        new("pbkdf2-twofish.bin", FixtureRole.Container,
            "The same inputs under Twofish-256-GCM. A regression vector: no Twofish-GCM implementation "
            + "exists outside BouncyCastle here, so the payload came from Enigma.Core. Its header — kcTag "
            + "included — is still independent.",
            ContainerMethodKind.Pbkdf2),

        // --- Method 0x02 — Argon2 ------------------------------------------------------------------
        new("argon2-aes.bin", FixtureRole.Container,
            "Argon2id 1.3 · AES-256-GCM · the same password, salt and nonce · 2 passes over 1,024 KiB, one "
            + "lane. Data key pinned by OpenSSL 3.6's ARGON2ID KDF; everything downstream rebuilt from "
            + "platform primitives at run time.",
            ContainerMethodKind.Argon2),
        new("argon2-twofish.bin", FixtureRole.Container,
            "The same inputs under Twofish-256-GCM — a regression vector, as for PBKDF2.",
            ContainerMethodKind.Argon2),

        // --- Method 0x03 — RSA ---------------------------------------------------------------------
        new("rsa-2048-public.pem", FixtureRole.Credential,
            "The RSA-2048 public key the two rsa-*.bin containers were written for."),
        new("rsa-2048-private.pem", FixtureRole.Credential,
            "Its unencrypted private half — the credential that opens them."),
        new("rsa-2048-private-encrypted.pem", FixtureRole.Credential,
            "The same private key in a PKCS#8 encrypted PEM, protected by "
            + "'enigma-test-pem-passphrase'. Exercises the keyPassword path, and — with a wrong passphrase — "
            + "the §9 rule that an undecryptable PEM is a DataDecryptionException."),
        new("rsa-aes.bin", FixtureRole.Container,
            "RSA · AES-256-GCM · data key 00–1F · nonce 00–0B · wrapped under rsa-2048-public.pem with "
            + "RSAES-OAEP-SHA256. The 256 wrapped-key bytes are OAEP-randomized and cannot be pinned; every "
            + "other byte is asserted exactly.",
            ContainerMethodKind.Rsa),
        new("rsa-twofish.bin", FixtureRole.Container,
            "The same inputs under Twofish-256-GCM — a regression vector for the payload, independent for "
            + "the header.",
            ContainerMethodKind.Rsa),

        // --- Method 0x04 — ML-KEM ------------------------------------------------------------------
        new("mlkem-512-public.key", FixtureRole.Credential,
            "The raw FIPS 203 ML-KEM-512 encapsulation key that mlkem-512-aes.bin was written for."),
        new("mlkem-512-private.key", FixtureRole.Credential,
            "Its raw expanded decapsulation key."),
        new("mlkem-512-secret.bin", FixtureRole.SharedSecret,
            "The 32-byte shared secret mlkem-512-aes.bin's encapsulation yields — the data key itself, "
            + "since §3.4 uses the KEM secret directly. Pins the KEM, which the write path cannot."),
        new("mlkem-512-aes.bin", FixtureRole.Container,
            "ML-KEM-512 (parameter-set byte 0x01) · AES-256-GCM · nonce 00–0B · 768-byte encapsulation.",
            ContainerMethodKind.MLKem, MLKemParameterSet.MLKem512, "512"),
        new("mlkem-1024-public.key", FixtureRole.Credential,
            "The raw FIPS 203 ML-KEM-1024 encapsulation key for the two mlkem-1024-*.bin containers."),
        new("mlkem-1024-private.key", FixtureRole.Credential,
            "Its raw expanded decapsulation key."),
        new("mlkem-1024-secret.bin", FixtureRole.SharedSecret,
            "The 32-byte shared secret the ML-KEM-1024 golden encapsulation yields."),
        new("mlkem-1024-aes.bin", FixtureRole.Container,
            "ML-KEM-1024 (parameter-set byte 0x03 — the default) · AES-256-GCM · nonce 00–0B · 1,568-byte "
            + "encapsulation.",
            ContainerMethodKind.MLKem, MLKemParameterSet.MLKem1024, "1024"),
        new("mlkem-1024-twofish.bin", FixtureRole.Container,
            "The same inputs under Twofish-256-GCM — a regression vector for the payload.",
            ContainerMethodKind.MLKem, MLKemParameterSet.MLKem1024, "1024"),
    ];

    /// <summary>The container fixtures alone, as theory data.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string> ContainerFixtureNames() =>
        [.. Inventory().Where(record => record.Role == FixtureRole.Container).Select(record => record.FileName)];

    /// <summary>All inventory rows, as theory data.</summary>
    /// <returns>The theory data.</returns>
    public static TheoryData<string> AllFixtureNames() =>
        [.. Inventory().Select(record => record.FileName)];

    /// <summary>
    /// The inventory and the directory agree in both directions: nothing committed is undocumented, and
    /// nothing documented is missing. This is the assertion that keeps the table honest — a fixture added
    /// without a row, or a row left behind after a file was deleted, fails here.
    /// </summary>
    [Fact]
    public void EveryCommittedFixtureIsInTheInventory()
    {
        string[] onDisk = [.. Directory
            .GetFiles(Path.Combine("Services", "Fixtures"))
            .Select(Path.GetFileName)
            .Where(name => name is not null)
            .Select(name => name!)
            .OrderBy(name => name, StringComparer.Ordinal)];

        string[] documented = [.. Inventory()
            .Select(record => record.FileName)
            .OrderBy(name => name, StringComparer.Ordinal)];

        Assert.Equal(documented, onDisk);
    }

    /// <summary>Every row describes itself — an undocumented fixture is as useless as a missing one.</summary>
    [Theory]
    [MemberData(nameof(AllFixtureNames))]
    public void EveryFixtureIsDescribedAndPresent(string fileName)
    {
        FixtureRecord record = Inventory().Single(candidate => candidate.FileName == fileName);

        Assert.NotEmpty(record.Description);
        Assert.NotEmpty(ContainerFixtures.Read(fileName));
    }

    /// <summary>
    /// Every container fixture decrypts, with the credential its row names, to the committed plaintext. This
    /// is what makes the inventory executable rather than decorative.
    /// </summary>
    [Theory]
    [MemberData(nameof(ContainerFixtureNames))]
    public async Task EveryContainerFixtureDecryptsToTheCommittedPlaintext(string fileName)
    {
        FixtureRecord record = Inventory().Single(candidate => candidate.FileName == fileName);
        byte[] container = ContainerFixtures.Read(fileName);
        byte[] expected = ContainerFixtures.Read("golden-plaintext.txt");

        byte[] recovered = record.Method switch
        {
            ContainerMethodKind.Pbkdf2 => await PasswordTestData.DecryptToBytesAsync(
                PasswordServiceAdapter.Create(PasswordMethod.Pbkdf2), container),
            ContainerMethodKind.Argon2 => await PasswordTestData.DecryptToBytesAsync(
                PasswordServiceAdapter.Create(PasswordMethod.Argon2), container),
            ContainerMethodKind.Rsa => await RsaTestData.DecryptToBytesAsync(
                RsaTestData.GoldenPrivateKeyPem(), container),
            _ => await MLKemTestData.DecryptToBytesAsync(
                MLKemTestData.GoldenPrivateKey(record.KeySlug!), container),
        };

        Assert.Equal(expected, recovered);
    }

    /// <summary>
    /// The method byte, the cipher byte and — for ML-KEM — the parameter-set byte on disk are the ones the
    /// row claims. A container fixture silently replaced by another method's would pass a round-trip test in
    /// the suite that owns it, but not this one.
    /// </summary>
    [Theory]
    [MemberData(nameof(ContainerFixtureNames))]
    public void EveryContainerFixtureCarriesTheHeaderBytesItsRowClaims(string fileName)
    {
        FixtureRecord record = Inventory().Single(candidate => candidate.FileName == fileName);
        byte[] container = ContainerFixtures.Read(fileName);

        Assert.Equal(0xEC, container[0]);
        Assert.Equal(0xDE, container[1]);
        Assert.Equal(ContainerMethodHarness.MethodByteOf(record.Method!.Value), container[2]);
        Assert.Equal(DataEncryptionDefaults.FormatVersion, container[3]);

        byte expectedCipher = fileName.Contains("twofish", StringComparison.Ordinal)
            ? (byte)Cipher.Twofish256Gcm
            : (byte)Cipher.Aes256Gcm;
        Assert.Equal(expectedCipher, container[4]);

        if (record.ParameterSet is { } parameterSet)
        {
            Assert.Equal(
                MLKemTestData.WireByteOf(parameterSet), container[MLKemTestData.ParameterSetOffset]);
        }
    }

    /// <summary>
    /// The committed ML-KEM shared secrets are what the committed encapsulations actually yield, checked
    /// against Enigma.Core's KEM directly rather than through this library.
    /// </summary>
    [Theory]
    [InlineData("512", MLKemParameterSet.MLKem512, "mlkem-512-aes.bin")]
    [InlineData("1024", MLKemParameterSet.MLKem1024, "mlkem-1024-aes.bin")]
    public void TheCommittedSharedSecretsMatchTheCommittedEncapsulations(
        string slug,
        MLKemParameterSet parameterSet,
        string containerFileName)
    {
        byte[] container = ContainerFixtures.Read(containerFileName);
        byte[] encapsulation = MLKemTestData.EncapsulationOf(
            container, MLKemTestData.EncapsulationLengthOf(parameterSet));

        byte[] secret = MLKemTestData.Decapsulate(
            encapsulation, MLKemTestData.GoldenPrivateKey(slug), parameterSet);

        Assert.Equal(MLKemTestData.GoldenSecret(slug), secret);
    }

    /// <summary>
    /// Between them, the container fixtures cover all four methods. A method whose read path has no
    /// committed fixture at all is the gap this asserts against.
    /// </summary>
    [Fact]
    public void EveryMethodHasAtLeastOneContainerFixture()
    {
        ContainerMethodKind[] covered = [.. Inventory()
            .Where(record => record.Role == FixtureRole.Container)
            .Select(record => record.Method!.Value)
            .Distinct()];

        Assert.Equal(ContainerMethodHarness.All.Length, covered.Length);
        foreach (ContainerMethodKind kind in ContainerMethodHarness.All)
        {
            Assert.Contains(kind, covered);
        }
    }

    /// <summary>What a committed fixture is for.</summary>
    public enum FixtureRole
    {
        /// <summary>A complete encrypted container, to be decrypted on the read path.</summary>
        Container,

        /// <summary>Key material — a PEM or raw KEM key — used to open a container.</summary>
        Credential,

        /// <summary>The plaintext a container must decrypt to.</summary>
        ExpectedPlaintext,

        /// <summary>A 32-byte ML-KEM shared secret, pinning the KEM itself.</summary>
        SharedSecret,
    }

    /// <summary>One row of the fixture inventory.</summary>
    /// <param name="FileName">The file's name within <c>Services/Fixtures</c>.</param>
    /// <param name="Role">What the file is for.</param>
    /// <param name="Description">Everything needed to reproduce or interpret it.</param>
    /// <param name="Method">The method a container fixture belongs to; <see langword="null"/> otherwise.</param>
    /// <param name="ParameterSet">The ML-KEM parameter set, where one applies.</param>
    /// <param name="KeySlug">The fixture slug of the key pair that opens a container, where one applies.</param>
    public sealed record FixtureRecord(
        string FileName,
        FixtureRole Role,
        string Description,
        ContainerMethodKind? Method = null,
        MLKemParameterSet? ParameterSet = null,
        string? KeySlug = null);
}
