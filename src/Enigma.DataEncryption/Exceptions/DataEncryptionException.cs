using System;

namespace Enigma.DataEncryption;

/// <summary>
/// Base class for the errors this library raises for a container it cannot process. Catch this type
/// to handle both failure kinds uniformly, or the derived types to distinguish them.
/// </summary>
/// <remarks>
/// <para>
/// The two derived types draw a deliberate line:
/// <see cref="DataEncryptionFormatException"/> means <i>this is not a container I can parse</i>,
/// while <see cref="DataDecryptionException"/> means <i>this is a valid container and I could not
/// open it</i> — in practice, the wrong credential.
/// </para>
/// <para>
/// Argument validation failures (<see cref="ArgumentNullException"/> and friends), cancellation
/// (<see cref="OperationCanceledException"/>) and credential-supply failures such as a malformed
/// private-key PEM are <b>not</b> represented by this hierarchy — they are not defects of the
/// container. See <c>docs/format.md</c> §9 for the complete mapping.
/// </para>
/// </remarks>
public abstract class DataEncryptionException : Exception
{
    /// <summary>Initializes a new instance with the specified message.</summary>
    /// <param name="message">A description of the error.</param>
    protected DataEncryptionException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with the specified message and inner exception.</summary>
    /// <param name="message">A description of the error.</param>
    /// <param name="innerException">The underlying exception that caused this error.</param>
    protected DataEncryptionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
