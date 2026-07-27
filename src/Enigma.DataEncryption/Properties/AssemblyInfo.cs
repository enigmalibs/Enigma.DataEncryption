using System.Runtime.CompilerServices;

// The library exposes an internal RNG seam (IRandomSource) so the unit tests can pin the encrypt
// path byte-for-byte against golden vectors. That seam is deliberately internal — a public hook for
// injecting randomness into a cryptography library is a footgun — so the test assembly needs
// friend access. Declared here rather than as an MSBuild AssemblyAttribute so the reason travels
// with the attribute.
[assembly: InternalsVisibleTo("Enigma.DataEncryption.UnitTests")]
