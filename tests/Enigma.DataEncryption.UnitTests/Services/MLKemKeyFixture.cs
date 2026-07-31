using System.Collections.Generic;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// Generate-once ML-KEM key material shared by every ML-KEM suite: a key pair for each of the three
/// parameter sets, plus a second, unrelated pair per set for the wrong-key cases.
/// </summary>
/// <remarks>
/// <para>
/// ML-KEM key generation is far cheaper than RSA's — six pairs take a few milliseconds rather than
/// seconds — so this fixture is about keeping the suites consistent rather than fast: every wrong-key test
/// is then wrong in the same way, against the same material, whichever class it lives in.
/// </para>
/// <para>
/// The generated pairs are <b>not</b> the committed golden-vector keys — those are fixture files, so the
/// golden containers stay reproducible across runs (see <see cref="MLKemGoldenVectorTests"/>). These are for
/// round-trips and failure cases, where only freshness matters.
/// </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public sealed class MLKemKeyFixture
{
    private readonly Dictionary<MLKemParameterSet, (byte[] PublicKey, byte[] PrivateKey)> _pairs = [];
    private readonly Dictionary<MLKemParameterSet, (byte[] PublicKey, byte[] PrivateKey)> _unrelated = [];

    /// <summary>Initializes the fixture, generating two key pairs for each parameter set.</summary>
    public MLKemKeyFixture()
    {
        IMLKemServiceFactory factory = new MLKemServiceFactory();

        foreach (MLKemParameterSet parameterSet in AllParameterSets)
        {
            IMLKemService service = factory.CreateMLKemService(parameterSet);
            _pairs[parameterSet] = service.GenerateKeyPair();
            _unrelated[parameterSet] = service.GenerateKeyPair();
        }
    }

    /// <summary>The three defined ML-KEM parameter sets, in wire-byte order.</summary>
    public static MLKemParameterSet[] AllParameterSets =>
        [MLKemParameterSet.MLKem512, MLKemParameterSet.MLKem768, MLKemParameterSet.MLKem1024];

    /// <summary>The public (encapsulation) key of the shared pair for a parameter set.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw FIPS 203 public key.</returns>
    public byte[] PublicKey(MLKemParameterSet parameterSet) => _pairs[parameterSet].PublicKey;

    /// <summary>The private (decapsulation) key of the shared pair for a parameter set.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw expanded FIPS 203 private key.</returns>
    public byte[] PrivateKey(MLKemParameterSet parameterSet) => _pairs[parameterSet].PrivateKey;

    /// <summary>The public key of the second, unrelated pair — the wrong key, on the encrypt side.</summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw FIPS 203 public key.</returns>
    public byte[] UnrelatedPublicKey(MLKemParameterSet parameterSet) => _unrelated[parameterSet].PublicKey;

    /// <summary>
    /// The private key of the second, unrelated pair — the wrong key, and the one FIPS 203 implicit
    /// rejection lets decapsulate <i>successfully</i> into a different shared secret.
    /// </summary>
    /// <param name="parameterSet">The parameter set.</param>
    /// <returns>The raw expanded FIPS 203 private key.</returns>
    public byte[] UnrelatedPrivateKey(MLKemParameterSet parameterSet) => _unrelated[parameterSet].PrivateKey;
}

/// <summary>Binds <see cref="MLKemKeyFixture"/> to the shared ML-KEM test collection.</summary>
// ReSharper disable once InconsistentNaming
[CollectionDefinition(Name)]
public sealed class MLKemKeyCollection : ICollectionFixture<MLKemKeyFixture>
{
    /// <summary>The collection name every ML-KEM suite joins.</summary>
    public const string Name = "mlkem-keys";
}
