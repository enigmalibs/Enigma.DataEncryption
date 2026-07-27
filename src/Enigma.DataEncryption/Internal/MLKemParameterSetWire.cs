using System;
using Enigma.Core.Asymmetric.Pqc;

namespace Enigma.DataEncryption.Internal;

/// <summary>
/// Translates between Enigma.Core's <see cref="MLKemParameterSet"/> and the header's parameter-set
/// byte at offset 5.
/// </summary>
/// <remarks>
/// <b>The wire byte is not the enum's numeric value.</b> <see cref="MLKemParameterSet"/> is a plain
/// unnumbered C# enum, so its members are <c>0</c>, <c>1</c> and <c>2</c>; the wire bytes are
/// <c>0x01</c>, <c>0x02</c> and <c>0x03</c>, deliberately 1-based so that <c>0x00</c> is never valid
/// and a zero-filled header cannot parse. Mapping must therefore be explicit — a cast would silently
/// shift every value by one. See <c>docs/format.md</c> §3.4.
/// </remarks>
internal static class MLKemParameterSetWire
{
    /// <summary>The header byte denoting ML-KEM-512.</summary>
    internal const byte MLKem512Byte = 0x01;

    /// <summary>The header byte denoting ML-KEM-768.</summary>
    internal const byte MLKem768Byte = 0x02;

    /// <summary>The header byte denoting ML-KEM-1024.</summary>
    internal const byte MLKem1024Byte = 0x03;

    /// <summary>Maps a parameter set to its header byte.</summary>
    /// <param name="parameterSet">The parameter set supplied by the caller.</param>
    /// <returns>The corresponding header byte.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="parameterSet"/> is not a defined value.</exception>
    internal static byte ToWireByte(MLKemParameterSet parameterSet) => parameterSet switch
    {
        MLKemParameterSet.MLKem512 => MLKem512Byte,
        MLKemParameterSet.MLKem768 => MLKem768Byte,
        MLKemParameterSet.MLKem1024 => MLKem1024Byte,
        _ => throw new ArgumentOutOfRangeException(
            nameof(parameterSet), parameterSet, "Undefined ML-KEM parameter set."),
    };

    /// <summary>Maps a header byte to its parameter set.</summary>
    /// <param name="value">The byte read from header offset 5.</param>
    /// <returns>The corresponding parameter set.</returns>
    /// <exception cref="DataEncryptionFormatException"><paramref name="value"/> is not a defined wire byte.</exception>
    internal static MLKemParameterSet FromWireByte(byte value) => value switch
    {
        MLKem512Byte => MLKemParameterSet.MLKem512,
        MLKem768Byte => MLKemParameterSet.MLKem768,
        MLKem1024Byte => MLKemParameterSet.MLKem1024,
        _ => throw new DataEncryptionFormatException(
            $"Undefined ML-KEM parameter-set byte 0x{value:X2} at header offset 5."),
    };
}
