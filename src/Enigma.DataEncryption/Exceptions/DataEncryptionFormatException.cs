using System;

namespace Enigma.DataEncryption;

/// <summary>
/// Thrown when a container's header cannot be parsed as a valid format-<c>0x10</c> container.
/// </summary>
/// <remarks>
/// <para>Raised for, among others:</para>
/// <list type="bullet">
///   <item><description>a magic that is not <c>EC DE</c>;</description></item>
///   <item><description>an undefined method byte, or one that does not match the service in use;</description></item>
///   <item><description>a format version other than <c>0x10</c>, including the reserved legacy range <c>0x01</c>–<c>0x0F</c>;</description></item>
///   <item><description>an undefined cipher byte or ML-KEM parameter-set byte;</description></item>
///   <item><description>a stream that ends inside the header;</description></item>
///   <item><description>a cost or length field that is <c>&lt;= 0</c> or exceeds its <see cref="DataEncryptionLimits"/> bound.</description></item>
/// </list>
/// <para>
/// This exception says nothing about the credential — it is raised before any credential is used. A
/// wrong password or key produces <see cref="DataDecryptionException"/> instead. See
/// <c>docs/format.md</c> §9.
/// </para>
/// </remarks>
public sealed class DataEncryptionFormatException : DataEncryptionException
{
    /// <summary>Initializes a new instance with the specified message.</summary>
    /// <param name="message">A description of the format violation.</param>
    public DataEncryptionFormatException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified message and inner exception.</summary>
    /// <param name="message">A description of the format violation.</param>
    /// <param name="innerException">The underlying exception that caused this error.</param>
    public DataEncryptionFormatException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
