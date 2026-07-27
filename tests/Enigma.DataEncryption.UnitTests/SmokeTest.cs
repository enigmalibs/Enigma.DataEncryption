using System.Reflection;
using Xunit;

namespace Enigma.DataEncryption.UnitTests;

/// <summary>
/// Bootstrap smoke test: proves the MTP-native xUnit v3 toolchain builds and runs green, and that
/// the library assembly this suite references actually loads at runtime on every test TFM.
/// <c>Enigma.DataEncryption</c> has no public types yet, so the assembly itself is all there is to
/// assert against. Expand once real types exist.
/// </summary>
public sealed class SmokeTest
{
    [Fact]
    public void LibraryAssembly_Loads()
    {
        Assembly assembly = Assembly.Load(new AssemblyName("Enigma.DataEncryption"));

        Assert.Equal("Enigma.DataEncryption", assembly.GetName().Name);
    }
}
