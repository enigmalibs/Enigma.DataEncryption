using Enigma.Core.Asymmetric.Pqc;

namespace Enigma.DataEncryption;

/// <summary>
/// The parsed, plaintext header of an encrypted container, as returned by
/// <see cref="IEncryptedDataInspector.ReadHeaderAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Method"/>, <see cref="FormatVersion"/>, <see cref="Cipher"/> and
/// <see cref="HeaderLength"/> are present on every container. Every other property is
/// method-specific and is <see langword="null"/> when it does not apply — see each property's own
/// documentation for which method populates it.
/// </para>
/// <para>
/// <b>The header carries no secret.</b> The salt, the GCM nonce, the wrapped key, the ML-KEM
/// encapsulation and the key-confirmation tag are all deliberately omitted: exposing them serves no
/// caller purpose. What is here is what a caller can act on — which credential is needed, how costly
/// the derivation will be, and where the payload starts.
/// </para>
/// <para>See <c>docs/format.md</c> §2 and §3.</para>
/// </remarks>
public sealed record EncryptedDataHeader
{
    /// <summary>
    /// The key-establishment method that produced the container, from header offset 2. Tells the
    /// caller which credential is required and which service can decrypt it.
    /// </summary>
    public required EncryptionMethod Method { get; init; }

    /// <summary>
    /// The container's format version, from header offset 3. Always
    /// <see cref="DataEncryptionDefaults.FormatVersion"/> (<c>0x10</c>) for containers this library
    /// can read; any other value is rejected while parsing.
    /// </summary>
    public required byte FormatVersion { get; init; }

    /// <summary>
    /// The AEAD block cipher protecting the payload, from header offset 4.
    /// </summary>
    public required Cipher Cipher { get; init; }

    /// <summary>
    /// The total header length in bytes — equivalently, the <b>offset of the first payload byte</b>.
    /// 53 for PBKDF2, 61 for Argon2, 37 + <see cref="WrappedKeyLength"/> for RSA, and
    /// 38 + <see cref="EncapsulationLength"/> for ML-KEM.
    /// </summary>
    public required int HeaderLength { get; init; }

    /// <summary>
    /// The ML-KEM parameter set the container was encapsulated under. Populated only when
    /// <see cref="Method"/> is <see cref="EncryptionMethod.MLKem"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public MLKemParameterSet? MLKemParameterSet { get; init; }

    /// <summary>
    /// The PBKDF2 iteration count stored in the header. Populated only when <see cref="Method"/> is
    /// <see cref="EncryptionMethod.Pbkdf2"/>; otherwise <see langword="null"/>.
    /// </summary>
    public int? Pbkdf2Iterations { get; init; }

    /// <summary>
    /// The Argon2 iteration count (passes over memory) stored in the header. Populated only when
    /// <see cref="Method"/> is <see cref="EncryptionMethod.Argon2"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public int? Argon2Iterations { get; init; }

    /// <summary>
    /// The Argon2 memory cost in kibibytes stored in the header. Populated only when
    /// <see cref="Method"/> is <see cref="EncryptionMethod.Argon2"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public int? Argon2MemorySizeKb { get; init; }

    /// <summary>
    /// The Argon2 degree of parallelism stored in the header. Populated only when
    /// <see cref="Method"/> is <see cref="EncryptionMethod.Argon2"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public int? Argon2DegreeOfParallelism { get; init; }

    /// <summary>
    /// The length in bytes of the RSAES-OAEP-wrapped data key. Populated only when
    /// <see cref="Method"/> is <see cref="EncryptionMethod.Rsa"/>; otherwise <see langword="null"/>.
    /// Equals the RSA modulus size in bytes.
    /// </summary>
    public int? WrappedKeyLength { get; init; }

    /// <summary>
    /// The length in bytes of the ML-KEM encapsulation (ciphertext). Populated only when
    /// <see cref="Method"/> is <see cref="EncryptionMethod.MLKem"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public int? EncapsulationLength { get; init; }
}
