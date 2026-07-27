using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Generate-once RSA key material shared by every RSA suite: three key sizes, an unrelated pair, and a
/// passphrase-protected private-key PEM.
/// </summary>
/// <remarks>
/// <para>
/// RSA key generation is the expensive part of these tests — roughly two seconds for all five pairs, and
/// far more than that if each test class generated its own. Enigma.Core's own <c>RsaKeyFixture</c> solves
/// this with a collection fixture; this is the same pattern, widened to the sizes and the wrong-key
/// material this phase needs.
/// </para>
/// <para>
/// The generated pairs are <b>not</b> the committed golden-vector key — that one is a fixture file, so the
/// golden containers stay reproducible across runs (see <c>RsaGoldenVectorTests</c>). These are for
/// round-trips and failure cases, where only freshness matters.
/// </para>
/// </remarks>
public sealed class RsaKeyFixture
{
    /// <summary>The passphrase protecting <see cref="EncryptedPrivateKeyPem"/>.</summary>
    public const string PemPassphrase = "pem-passphrase";

    /// <summary>Initializes the fixture, generating every key pair the RSA suites share.</summary>
    public RsaKeyFixture()
    {
        IPublicKeyService service = new PublicKeyServiceFactory().CreatePublicKeyService();

        (PublicKeyPem, PrivateKeyPem) = service.GenerateRsaKeyPair(2048);
        (PublicKeyPem3072, PrivateKeyPem3072) = service.GenerateRsaKeyPair(3072);
        (PublicKeyPem4096, PrivateKeyPem4096) = service.GenerateRsaKeyPair(4096);
        (UnrelatedPublicKeyPem, UnrelatedPrivateKeyPem) = service.GenerateRsaKeyPair(2048);

        // An encrypted private-key PEM in BouncyCastle's traditional OpenSSL envelope
        // (RSA PRIVATE KEY + Proc-Type: 4,ENCRYPTED). The committed fixture is a PKCS#8
        // ENCRYPTED PRIVATE KEY instead, so both flavours are exercised.
        (EncryptedPemPublicKeyPem, EncryptedPrivateKeyPem) =
            service.GenerateRsaKeyPair(2048, PemPassphrase.ToCharArray());
    }

    /// <summary>A 2048-bit RSA public key, PEM-encoded.</summary>
    public string PublicKeyPem { get; }

    /// <summary>The matching unencrypted 2048-bit private key, PEM-encoded.</summary>
    public string PrivateKeyPem { get; }

    /// <summary>A 3072-bit RSA public key, PEM-encoded.</summary>
    public string PublicKeyPem3072 { get; }

    /// <summary>The matching unencrypted 3072-bit private key, PEM-encoded.</summary>
    public string PrivateKeyPem3072 { get; }

    /// <summary>A 4096-bit RSA public key, PEM-encoded.</summary>
    public string PublicKeyPem4096 { get; }

    /// <summary>The matching unencrypted 4096-bit private key, PEM-encoded.</summary>
    public string PrivateKeyPem4096 { get; }

    /// <summary>A second, unrelated 2048-bit public key — the wrong key, in the tests that need one.</summary>
    public string UnrelatedPublicKeyPem { get; }

    /// <summary>The matching unencrypted private key of the unrelated pair.</summary>
    public string UnrelatedPrivateKeyPem { get; }

    /// <summary>The public key whose private half is <see cref="EncryptedPrivateKeyPem"/>.</summary>
    public string EncryptedPemPublicKeyPem { get; }

    /// <summary>A 2048-bit private key in an encrypted PEM, protected by <see cref="PemPassphrase"/>.</summary>
    public string EncryptedPrivateKeyPem { get; }

    /// <summary>A fresh copy of <see cref="PemPassphrase"/> as characters.</summary>
    /// <returns>The passphrase characters.</returns>
    public char[] PemPassphraseChars() => PemPassphrase.ToCharArray();
}

/// <summary>Binds <see cref="RsaKeyFixture"/> to the shared RSA test collection.</summary>
[CollectionDefinition(Name)]
public sealed class RsaKeyCollection : ICollectionFixture<RsaKeyFixture>
{
    /// <summary>The collection name every RSA suite joins.</summary>
    public const string Name = "rsa-keys";
}
