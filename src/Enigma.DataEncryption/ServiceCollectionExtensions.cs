using System;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.KeyDerivation;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.DataEncryption;
using Enigma.DataEncryption.Internal;
using Microsoft.Extensions.DependencyInjection.Extensions;

// Sits in Microsoft.Extensions.DependencyInjection rather than Enigma.DataEncryption so that
// AddEnigmaDataEncryption() is discoverable on IServiceCollection without an extra using directive —
// the convention every Microsoft.Extensions.* registration extension follows.
// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers Enigma.DataEncryption's services with a <see cref="IServiceCollection"/>.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the four encryption services, the inspector, and the Enigma.Core factories they
    /// depend on.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <remarks>
    /// <para>Registers, all as singletons:</para>
    /// <list type="bullet">
    ///   <item><description><see cref="IPbkdf2DataEncryptionService"/>, <see cref="IArgon2DataEncryptionService"/>, <see cref="IRsaDataEncryptionService"/>, <see cref="IMLKemDataEncryptionService"/> and <see cref="IEncryptedDataInspector"/>;</description></item>
    ///   <item><description>the Enigma.Core factories those services consume — <see cref="IBlockCipherServiceFactory"/>, <see cref="IPbkdf2ServiceFactory"/>, <see cref="IArgon2ServiceFactory"/>, <see cref="IPublicKeyServiceFactory"/>, <see cref="IMLKemServiceFactory"/> and <see cref="IHmacServiceFactory"/>. Enigma.Core deliberately ships no <c>AddEnigmaCore</c>, so registering them is this method's responsibility.</description></item>
    /// </list>
    /// <para>
    /// <b>Singleton is correct</b> because every one of these services is stateless and thread-safe —
    /// all per-operation state (keys, nonces, buffers) lives on the stack of the call.
    /// </para>
    /// <para>
    /// <b>Every registration uses <c>TryAdd</c></b>, so a consumer who has already registered their
    /// own implementation of any of these — a custom <see cref="IBlockCipherServiceFactory"/>, say —
    /// keeps it. Calling this method twice is harmless.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/>.</exception>
    public static IServiceCollection AddEnigmaDataEncryption(this IServiceCollection services)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));

        // Enigma.Core primitives. All are sealed, parameterless and stateless.
        services.TryAddSingleton<IBlockCipherServiceFactory, BlockCipherServiceFactory>();
        services.TryAddSingleton<IPbkdf2ServiceFactory, Pbkdf2ServiceFactory>();
        services.TryAddSingleton<IArgon2ServiceFactory, Argon2ServiceFactory>();
        services.TryAddSingleton<IPublicKeyServiceFactory, PublicKeyServiceFactory>();
        services.TryAddSingleton<IMLKemServiceFactory, MLKemServiceFactory>();
        services.TryAddSingleton<IHmacServiceFactory, HmacServiceFactory>();

        // The internal RNG seam. Not part of the public surface, so it cannot appear on a public
        // constructor; the services below are therefore built through explicit factories that reach
        // their internal constructor. That is what makes this registration substitutable.
        services.TryAddSingleton<IRandomSource, RandomSource>();

        // This library's own services.
        services.TryAddSingleton<IPbkdf2DataEncryptionService>(sp => new Pbkdf2DataEncryptionService(
            sp.GetRequiredService<IBlockCipherServiceFactory>(),
            sp.GetRequiredService<IPbkdf2ServiceFactory>(),
            sp.GetRequiredService<IHmacServiceFactory>(),
            sp.GetRequiredService<IRandomSource>()));

        services.TryAddSingleton<IArgon2DataEncryptionService>(sp => new Argon2DataEncryptionService(
            sp.GetRequiredService<IBlockCipherServiceFactory>(),
            sp.GetRequiredService<IArgon2ServiceFactory>(),
            sp.GetRequiredService<IHmacServiceFactory>(),
            sp.GetRequiredService<IRandomSource>()));

        services.TryAddSingleton<IRsaDataEncryptionService>(sp => new RsaDataEncryptionService(
            sp.GetRequiredService<IBlockCipherServiceFactory>(),
            sp.GetRequiredService<IPublicKeyServiceFactory>(),
            sp.GetRequiredService<IHmacServiceFactory>(),
            sp.GetRequiredService<IRandomSource>()));

        services.TryAddSingleton<IMLKemDataEncryptionService>(sp => new MLKemDataEncryptionService(
            sp.GetRequiredService<IBlockCipherServiceFactory>(),
            sp.GetRequiredService<IMLKemServiceFactory>(),
            sp.GetRequiredService<IHmacServiceFactory>(),
            sp.GetRequiredService<IRandomSource>()));

        services.TryAddSingleton<IEncryptedDataInspector, EncryptedDataInspector>();

        return services;
    }
}
