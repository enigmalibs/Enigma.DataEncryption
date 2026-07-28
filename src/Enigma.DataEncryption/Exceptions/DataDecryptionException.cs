using System;

namespace Enigma.DataEncryption;

/// <summary>
/// Thrown when a well-formed container cannot be decrypted — in practice, the wrong credential.
/// </summary>
/// <remarks>
/// <para>Raised for:</para>
/// <list type="bullet">
///   <item><description>a key-confirmation tag mismatch — the uniform, fast wrong-credential signal, reported before a single payload byte is read;</description></item>
///   <item><description>a GCM authentication failure, wrapping the underlying <see cref="System.Security.Cryptography.CryptographicException"/>;</description></item>
///   <item><description>an RSAES-OAEP unwrap failure, likewise wrapping the underlying <see cref="System.Security.Cryptography.CryptographicException"/>.</description></item>
/// </list>
/// <para>
/// A malformed or undecryptable private-key PEM is <b>not</b> reported through this type: that is a
/// credential-supply error rather than a container error, and Enigma.Core's own exception propagates
/// unwrapped. See <c>docs/format.md</c> §9.
/// </para>
/// <para>
/// The message deliberately does not distinguish <i>which</i> check failed beyond what the caller
/// needs, and the key-confirmation comparison itself is constant-time.
/// </para>
/// </remarks>
public sealed class DataDecryptionException : DataEncryptionException
{
    /// <summary>Initializes a new instance with the specified message.</summary>
    /// <param name="message">A description of the decryption failure.</param>
    public DataDecryptionException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified message and inner exception.</summary>
    /// <param name="message">A description of the decryption failure.</param>
    /// <param name="innerException">The underlying exception that caused this error.</param>
    public DataDecryptionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
