using System.Collections.Generic;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Generate-once key material for the hybrid suites: the RSA pairs and the ML-KEM pairs, plus a second,
/// unrelated pair of each, so that "one credential wrong" can be arranged in either half independently.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a fixture of its own rather than joining <see cref="RsaKeyCollection"/> and
/// <see cref="MLKemKeyCollection"/>.</b> A test class belongs to one collection, and collection fixtures
/// are per-collection, so the hybrid suites could not share both of the existing ones. Reusing one of them
/// would serialize six new classes behind the suites already in it; a collection of its own keeps them
/// running alongside. The price is one extra round of RSA generation for the whole test run.
/// </para>
/// <para>
/// The sizes are the ones this method's round-trips need — 2048 and 3072 — rather than every size the RSA
/// suites cover: what the hybrid adds is the <i>pairing</i> of two primitives, not RSA modulus coverage,
/// which <c>RsaRoundTripTests</c> already has.
/// </para>
/// <para>
/// These are <b>not</b> the committed golden-vector keys. Those are fixture files, so the golden containers
/// stay reproducible across runs (see <see cref="HybridGoldenVectorTests"/>); these are for round-trips and
/// failure cases, where only freshness matters.
/// </para>
/// </remarks>
public sealed class HybridKeyFixture
{
    /// <summary>The passphrase protecting <see cref="EncryptedRsaPrivateKeyPem"/>.</summary>
    public const string PemPassphrase = "hybrid-pem-passphrase";

    private readonly Dictionary<MLKemParameterSet, (byte[] PublicKey, byte[] PrivateKey)> _kemPairs = [];
    private readonly Dictionary<MLKemParameterSet, (byte[] PublicKey, byte[] PrivateKey)> _kemUnrelated = [];

    /// <summary>Initializes the fixture, generating every key pair the hybrid suites share.</summary>
    public HybridKeyFixture()
    {
        IPublicKeyService rsa = new PublicKeyServiceFactory().CreatePublicKeyService();

        (RsaPublicKeyPem, RsaPrivateKeyPem) = rsa.GenerateRsaKeyPair(2048);
        (RsaPublicKeyPem3072, RsaPrivateKeyPem3072) = rsa.GenerateRsaKeyPair(3072);
        (UnrelatedRsaPublicKeyPem, UnrelatedRsaPrivateKeyPem) = rsa.GenerateRsaKeyPair(2048);
        (EncryptedPemRsaPublicKeyPem, EncryptedRsaPrivateKeyPem) =
            rsa.GenerateRsaKeyPair(2048, PemPassphrase.ToCharArray());

        IMLKemServiceFactory kemFactory = new MLKemServiceFactory();
        foreach (MLKemParameterSet parameterSet in AllParameterSets)
        {
            IMLKemService kem = kemFactory.CreateMLKemService(parameterSet);
            _kemPairs[parameterSet] = kem.GenerateKeyPair();
            _kemUnrelated[parameterSet] = kem.GenerateKeyPair();
        }
    }

    /// <summary>The three defined ML-KEM parameter sets, in wire-byte order.</summary>
    public static MLKemParameterSet[] AllParameterSets =>
        [MLKemParameterSet.MLKem512, MLKemParameterSet.MLKem768, MLKemParameterSet.MLKem1024];

    /// <summary>A 2048-bit RSA public key, PEM-encoded.</summary>
    public string RsaPublicKeyPem { get; }

    /// <summary>The matching unencrypted 2048-bit private key, PEM-encoded.</summary>
    public string RsaPrivateKeyPem { get; }

    /// <summary>A 3072-bit RSA public key, PEM-encoded.</summary>
    public string RsaPublicKeyPem3072 { get; }

    /// <summary>The matching unencrypted 3072-bit private key, PEM-encoded.</summary>
    public string RsaPrivateKeyPem3072 { get; }

    /// <summary>A second, unrelated 2048-bit RSA public key — the wrong RSA key, on the encrypt side.</summary>
    public string UnrelatedRsaPublicKeyPem { get; }

    /// <summary>The matching private key of the unrelated RSA pair — the wrong RSA key, on the decrypt side.</summary>
    public string UnrelatedRsaPrivateKeyPem { get; }

    /// <summary>The public key whose private half is <see cref="EncryptedRsaPrivateKeyPem"/>.</summary>
    public string EncryptedPemRsaPublicKeyPem { get; }

    /// <summary>A 2048-bit RSA private key in an encrypted PEM, protected by <see cref="PemPassphrase"/>.</summary>
    public string EncryptedRsaPrivateKeyPem { get; }

    /// <summary>A fresh copy of <see cref="PemPassphrase"/> as characters.</summary>
    /// <returns>The passphrase characters.</returns>
    public char[] PemPassphraseChars() => PemPassphrase.ToCharArray();

    /// <summary>The ML-KEM public (encapsulation) key of the shared pair for a parameter set.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw FIPS 203 public key.</returns>
    public byte[] MLKemPublicKey(MLKemParameterSet parameterSet) => _kemPairs[parameterSet].PublicKey;

    /// <summary>The ML-KEM private (decapsulation) key of the shared pair for a parameter set.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw expanded FIPS 203 private key.</returns>
    public byte[] MLKemPrivateKey(MLKemParameterSet parameterSet) => _kemPairs[parameterSet].PrivateKey;

    /// <summary>The ML-KEM public key of the second, unrelated pair.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw FIPS 203 public key.</returns>
    public byte[] UnrelatedMLKemPublicKey(MLKemParameterSet parameterSet) =>
        _kemUnrelated[parameterSet].PublicKey;

    /// <summary>
    /// The ML-KEM private key of the second, unrelated pair — the wrong ML-KEM key, and the one FIPS 203
    /// implicit rejection lets decapsulate <i>successfully</i> into a different shared secret. That is what
    /// makes it the sharper of the two halves to get wrong: nothing but the combined key's confirmation tag
    /// can notice.
    /// </summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw expanded FIPS 203 private key.</returns>
    public byte[] UnrelatedMLKemPrivateKey(MLKemParameterSet parameterSet) =>
        _kemUnrelated[parameterSet].PrivateKey;
}

/// <summary>Binds <see cref="HybridKeyFixture"/> to the shared hybrid test collection.</summary>
[CollectionDefinition(Name)]
public sealed class HybridKeyCollection : ICollectionFixture<HybridKeyFixture>
{
    /// <summary>The collection name every hybrid suite joins.</summary>
    public const string Name = "hybrid-keys";
}
