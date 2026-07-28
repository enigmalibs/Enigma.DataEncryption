using System;
using System.Linq;
using System.Reflection;
using Enigma.DataEncryption;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Api;

/// <summary>
/// The format machinery under <c>Enigma.DataEncryption.Internal</c> must stay internal: it is a set of
/// implementation seams — a header parser, a randomness hook, a cipher-factory adapter — none of which
/// this library wants to be held to as a public contract.
/// </summary>
/// <remarks>
/// A reflection guard rather than a review habit, for the same reason as
/// <see cref="BouncyCastleIsolationTests"/>: <c>internal</c> is one keyword away from <c>public</c>, and
/// nothing else in the build would notice. <c>InternalsVisibleTo</c> grants the test assembly access
/// without exporting anything, which is exactly the distinction being asserted here.
/// </remarks>
public sealed class InternalSurfaceIsolationTests
{
    private const string InternalNamespace = "Enigma.DataEncryption.Internal";

    [Fact]
    public void NoTypeInTheInternalNamespace_IsExported()
    {
        Assembly assembly = typeof(DataEncryptionDefaults).Assembly;

        string[] exported = assembly
            .GetExportedTypes()
            .Where(type => type.Namespace is { } ns &&
                           (ns == InternalNamespace ||
                            ns.StartsWith(InternalNamespace + ".", StringComparison.Ordinal)))
            .Select(type => type.FullName!)
            .ToArray();

        Assert.True(
            exported.Length == 0,
            "Internal format machinery leaked onto the public surface:" + Environment.NewLine +
            string.Join(Environment.NewLine, exported));
    }

    /// <summary>
    /// Guards the guard: the sweep above would pass vacuously if the namespace were renamed, so assert
    /// the types really are there and really are non-public.
    /// </summary>
    [Fact]
    public void TheInternalNamespace_IsPopulatedAndEntirelyNonPublic()
    {
        Assembly assembly = typeof(DataEncryptionDefaults).Assembly;

        Type[] internalTypes = assembly
            .GetTypes()
            .Where(type => type.Namespace == InternalNamespace)
            .ToArray();

        Assert.NotEmpty(internalTypes);
        Assert.All(internalTypes, type => Assert.False(type.IsPublic));
    }
}
