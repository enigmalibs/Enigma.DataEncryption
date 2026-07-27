using System;
using System.Text;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// The password credential the two KDF-based methods share: its validation, and the UTF-8 encoding of
/// the <see cref="char"/>-array form.
/// </summary>
/// <remarks>
/// <para>
/// <b>The caller's array is never touched.</b> The <see cref="char"/> overloads encode into a fresh
/// buffer, which the calling service clears in a <c>finally</c>; the caller keeps ownership of both the
/// characters they passed and — for the <see cref="byte"/> form — of the encoding they chose. That is
/// what the XML docs on the two service interfaces promise.
/// </para>
/// <para>
/// The encoding is UTF-8 and is not configurable. A password is only ever compared against itself
/// through the derived key, so the one thing that matters is that both directions encode identically —
/// and the container carries no encoding field to disagree about.
/// </para>
/// </remarks>
internal static class PasswordCredential
{
    /// <summary>Validates a password supplied as raw bytes.</summary>
    /// <param name="password">The caller's password bytes.</param>
    /// <param name="paramName">The name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    internal static void Validate(byte[] password, string paramName)
    {
        if (password is null) throw new ArgumentNullException(paramName);
        if (password.Length == 0)
        {
            throw new ArgumentException("The password must not be empty.", paramName);
        }
    }

    /// <summary>Validates a password supplied as characters.</summary>
    /// <param name="password">The caller's password characters.</param>
    /// <param name="paramName">The name of the caller's parameter, for the exception.</param>
    /// <exception cref="ArgumentNullException"><paramref name="password"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    internal static void Validate(char[] password, string paramName)
    {
        if (password is null) throw new ArgumentNullException(paramName);
        if (password.Length == 0)
        {
            throw new ArgumentException("The password must not be empty.", paramName);
        }
    }

    /// <summary>UTF-8-encodes a password into a new buffer for the caller to clear.</summary>
    /// <param name="password">The password characters, left untouched.</param>
    /// <returns>The UTF-8 bytes.</returns>
    internal static byte[] Encode(char[] password) => Encoding.UTF8.GetBytes(password);
}
