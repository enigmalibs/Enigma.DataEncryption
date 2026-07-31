namespace Enigma.DataEncryption;

/// <summary>
/// Upper bounds applied to the cost and length fields read from a container header.
/// </summary>
/// <remarks>
/// <para>
/// Every bound is checked <b>before any allocation or key-derivation work</b>. That ordering is the
/// entire point: a hostile header claiming two billion Argon2 iterations, or a gigabyte-long wrapped
/// key, must be rejected by arithmetic rather than survived by computation. A field that is
/// <c>&lt;= 0</c> or above its bound raises <see cref="DataEncryptionFormatException"/>.
/// </para>
/// <para>
/// The defaults are generous relative to legitimate use — they say what is <i>survivable</i>, not
/// what is <i>sensible</i>. Pass a customised instance to any <c>DecryptAsync</c> overload to tighten
/// them; passing <see langword="null"/> uses <see cref="Default"/>.
/// </para>
/// <para>See <c>docs/format.md</c> §8.</para>
/// </remarks>
public sealed class DataEncryptionLimits
{
    /// <summary>
    /// The shared instance carrying the default bounds, used whenever a <c>limits</c> argument is
    /// <see langword="null"/>. Instances are immutable, so this may be shared freely.
    /// </summary>
    public static DataEncryptionLimits Default { get; } = new();

    /// <summary>
    /// The largest PBKDF2 iteration count accepted from a header. Defaults to 10,000,000.
    /// </summary>
    public int MaxPbkdf2Iterations { get; init; } = 10_000_000;

    /// <summary>
    /// The largest Argon2 iteration count (passes over memory) accepted from a header. Defaults to 64.
    /// </summary>
    public int MaxArgon2Iterations { get; init; } = 64;

    /// <summary>
    /// The largest Argon2 memory cost, in kibibytes, accepted from a header. Defaults to 1,048,576
    /// KiB (1 GiB).
    /// </summary>
    public int MaxArgon2MemorySizeKb { get; init; } = 1_048_576;

    /// <summary>
    /// The largest Argon2 degree of parallelism accepted from a header. Defaults to 64.
    /// </summary>
    public int MaxArgon2DegreeOfParallelism { get; init; } = 64;

    /// <summary>
    /// The largest RSA wrapped-key length, in bytes, accepted from a header. Defaults to 4,096 —
    /// comfortably above the 512 bytes an RSA-4096 key produces.
    /// </summary>
    public int MaxWrappedKeyLength { get; init; } = 4_096;

    /// <summary>
    /// The largest ML-KEM encapsulation length, in bytes, accepted from a header. Defaults to 4,096;
    /// the true maximum is 1,568 (ML-KEM-1024).
    /// </summary>
    public int MaxEncapsulationLength { get; init; } = 4_096;
}
