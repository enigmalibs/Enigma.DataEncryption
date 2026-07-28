using System;
using System.IO;

namespace Enigma.DataEncryption.UnitTests.Services;

/// <summary>
/// A private directory under the system temp path, removed when the test finishes.
/// </summary>
/// <remarks>
/// The file-path extension methods can only be tested against real files — <c>FileMode.Create</c>,
/// <c>FileShare</c> and "the partial output was deleted" have no in-memory equivalent. Each test gets its
/// own directory so a leftover file from one can never be mistaken for the file another is asserting
/// about, and so the suite stays safe to run in parallel.
/// </remarks>
internal sealed class TempWorkspace : IDisposable
{
    private readonly string _root;

    /// <summary>Creates a uniquely named directory.</summary>
    internal TempWorkspace()
    {
        _root = Path.Combine(Path.GetTempPath(), "enigma-de-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    /// <summary>A path inside the workspace. The file itself is not created.</summary>
    /// <param name="fileName">The file name.</param>
    /// <returns>The absolute path.</returns>
    internal string PathFor(string fileName) => Path.Combine(_root, fileName);

    /// <summary>Writes a file inside the workspace and returns its path.</summary>
    /// <param name="fileName">The file name.</param>
    /// <param name="content">The bytes to write.</param>
    /// <returns>The absolute path.</returns>
    internal string WriteFile(string fileName, byte[] content)
    {
        string path = PathFor(fileName);
        File.WriteAllBytes(path, content);
        return path;
    }

    /// <summary>Removes the directory and everything in it, best-effort.</summary>
    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a passing test over.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
