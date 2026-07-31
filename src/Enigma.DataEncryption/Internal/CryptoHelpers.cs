using System;
#if !NETSTANDARD2_0
using System.Security.Cryptography;
#endif

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Small cryptographic primitives the library needs on every target framework: a constant-time
/// comparison and a buffer-zeroing helper.
/// </summary>
internal static class CryptoHelpers
{
    /// <summary>
    /// Compares two byte arrays in time that does not depend on <b>where</b> they differ.
    /// </summary>
    /// <param name="left">The first array. May be <see langword="null"/>.</param>
    /// <param name="right">The second array. May be <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> only when both arrays are non-null, of equal length, and equal in every
    /// byte.
    /// </returns>
    /// <remarks>
    /// A length mismatch returns <see langword="false"/> without comparing any byte: the lengths of
    /// the values compared here (a 16-byte key-confirmation tag) are fixed by the format and public,
    /// so they are not secret. What must not leak is the position of the first differing byte, and
    /// that is what the XOR accumulator below — and
    /// <c>CryptographicOperations.FixedTimeEquals</c> on the modern targets — protect.
    /// </remarks>
    internal static bool FixedTimeEquals(byte[]? left, byte[]? right)
    {
        if (left is null || right is null) return false;
        if (left.Length != right.Length) return false;

#if NETSTANDARD2_0
        // No CryptographicOperations on netstandard2.0. Accumulate the difference over the whole
        // array — no early return, no branch on the data.
        int difference = 0;
        for (int i = 0; i < left.Length; i++)
        {
            difference |= left[i] ^ right[i];
        }

        return difference == 0;
#else
        return CryptographicOperations.FixedTimeEquals(left, right);
#endif
    }

    /// <summary>
    /// Zeroes every supplied buffer, ignoring those that are <see langword="null"/> or empty.
    /// </summary>
    /// <param name="buffers">The buffers to clear.</param>
    /// <remarks>
    /// Call this from a <c>finally</c> that encloses <b>all</b> uses of the key material, never after
    /// the last use on the happy path — an exception thrown in between would otherwise leave the key
    /// in memory. The predecessor library's code review raised exactly that as its one High-severity
    /// finding.
    /// </remarks>
    internal static void Clear(params byte[]?[] buffers)
    {
        if (buffers is null) return;

        foreach (byte[]? buffer in buffers)
        {
            if (buffer is null || buffer.Length == 0) continue;

#if NETSTANDARD2_0
            Array.Clear(buffer, 0, buffer.Length);
#else
            CryptographicOperations.ZeroMemory(buffer);
#endif
        }
    }
}
