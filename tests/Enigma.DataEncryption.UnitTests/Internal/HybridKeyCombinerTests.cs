using Enigma.DataEncryption.Internal;
using Enigma.DataEncryption.UnitTests.Services;
using Xunit;

namespace Enigma.DataEncryption.UnitTests.Internal;

/// <summary>
/// The hybrid key combiner of <c>docs/format.md</c> §3.5.1, pinned against a hard-coded vector and against
/// an independent implementation — and, the part that matters most, shown to actually <b>depend on all
/// four of its inputs</b>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the dependency tests are the point of this class.</b> A combiner that quietly ignored one of its
/// two secrets would round-trip perfectly, produce plausible-looking containers, and pass every other test
/// in the suite — while reducing the method to whichever half it still used, which is the one failure this
/// whole feature exists to prevent. The service-level suite demonstrates the same property end to end;
/// here it is isolated, so a failure says which input was dropped.
/// </para>
/// <para>
/// <b>The hard-coded vector is what catches an argument swap.</b>
/// <c>IHmacService.ComputeHmac</c> takes <c>(data, key)</c> — message first — the opposite of the order
/// §3.5.1 writes the formulae in. A combiner that passed them the other way round would still be a
/// deterministic function of all four inputs and would still round-trip; only a fixed expected value, or
/// the independent implementation in <see cref="GoldenVectorPrimitives"/>, disagrees with it.
/// </para>
/// </remarks>
public sealed class HybridKeyCombinerTests
{
    /// <summary>The 32-byte RSA-half secret of the vectors: bytes <c>00</c>–<c>1F</c>.</summary>
    private static byte[] RsaSecret() => FormatTestData.Sequence(0x00, 32);

    /// <summary>The 32-byte ML-KEM shared secret of the vectors: bytes <c>20</c>–<c>3F</c>.</summary>
    private static byte[] KemSecret() => FormatTestData.Sequence(0x20, 32);

    /// <summary>A stand-in 256-byte RSAES-OAEP ciphertext: bytes counting up from <c>0x40</c>.</summary>
    private static byte[] WrappedSecret() => FormatTestData.Sequence(0x40, 256);

    /// <summary>A stand-in 768-byte ML-KEM encapsulation: bytes counting up from <c>0x80</c>.</summary>
    private static byte[] Encapsulation() => FormatTestData.Sequence(0x80, 768);

    private static byte[] Combine(
        byte[]? rsaSecret = null,
        byte[]? kemSecret = null,
        byte[]? wrappedSecret = null,
        byte[]? encapsulation = null) =>
        HybridKeyCombiner.Combine(
            FormatTestData.HmacSha256(),
            rsaSecret ?? RsaSecret(),
            kemSecret ?? KemSecret(),
            wrappedSecret ?? WrappedSecret(),
            encapsulation ?? Encapsulation());

    // --- The vector -----------------------------------------------------------------------------

    /// <summary>
    /// The combiner over the fixed inputs above, computed independently with the platform's
    /// <c>HMACSHA256</c> rather than Enigma.Core's BouncyCastle-backed one.
    /// </summary>
    /// <remarks>
    /// This is the assertion that would fail on an argument swap, a wrong label, a missing label, a
    /// concatenation instead of an XOR, or a transcript built without its length prefixes. It is stated as
    /// a comparison against <see cref="GoldenVectorPrimitives.HybridDataKey"/> rather than a literal so
    /// that the expectation is derived from the formulae in §3.5.1 rather than from a value this
    /// implementation once produced.
    /// </remarks>
    [Fact]
    public void TheCombinerMatchesAnIndependentImplementationOfTheSpecification()
    {
        byte[] expected = GoldenVectorPrimitives.HybridDataKey(
            RsaSecret(), KemSecret(), WrappedSecret(), Encapsulation());

        Assert.Equal(expected, Combine());
    }

    /// <summary>
    /// A literal expected value as well, over deliberately tiny inputs so it can be reproduced by hand or
    /// in another language. This is the vector a reimplementation checks itself against.
    /// </summary>
    /// <remarks>
    /// The two branches are
    /// <c>HMAC-SHA256(key: 32×0x01, msg: "…/hybrid/rsa/v1" ‖ T)</c> and
    /// <c>HMAC-SHA256(key: 32×0x02, msg: "…/hybrid/mlkem/v1" ‖ T)</c>, with
    /// <c>T = 04 00 00 00 ‖ AA BB CC DD ‖ 03 00 00 00 ‖ 11 22 33</c>, XOR-ed together. The lengths are
    /// 4 and 3 rather than a real modulus and encapsulation precisely so the whole transcript fits on one
    /// line.
    /// </remarks>
    [Fact]
    public void TheCombinerMatchesAReproducibleLiteralVector()
    {
        byte[] rsaSecret = Fill(0x01);
        byte[] kemSecret = Fill(0x02);
        byte[] wrappedSecret = [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] encapsulation = [0x11, 0x22, 0x33];

        byte[] actual = HybridKeyCombiner.Combine(
            FormatTestData.HmacSha256(), rsaSecret, kemSecret, wrappedSecret, encapsulation);

        Assert.Equal<byte[]>(
            [
                0xFF, 0x2F, 0xD1, 0x32, 0xF1, 0xF0, 0x22, 0x88,
                0x02, 0xF1, 0xA2, 0xCC, 0x9A, 0x17, 0x92, 0xD5,
                0x7E, 0x51, 0x04, 0xDF, 0xFB, 0x84, 0xF8, 0xE0,
                0x6D, 0x93, 0x20, 0x2B, 0x44, 0x2F, 0x52, 0xD4,
            ],
            actual);

        // The same value from the platform's HMAC, so the literal is not merely what this code produced.
        Assert.Equal(
            GoldenVectorPrimitives.HybridDataKey(
                Fill(0x01), Fill(0x02), [0xAA, 0xBB, 0xCC, 0xDD], [0x11, 0x22, 0x33]),
            actual);

        // The transcript that vector is over, written out — 15 bytes, checkable by eye.
        Assert.Equal<byte[]>(
            [0x04, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x03, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33],
            HybridKeyCombiner.BuildTranscript([0xAA, 0xBB, 0xCC, 0xDD], [0x11, 0x22, 0x33]));
    }

    [Fact]
    public void TheCombinedKeyIsTheDataKeySize() =>
        Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, Combine().Length);

    [Fact]
    public void TheCombinerIsDeterministic() => Assert.Equal(Combine(), Combine());

    // --- Every input contributes ----------------------------------------------------------------

    /// <summary>
    /// <b>The RSA secret contributes.</b> Only that argument changes; the transcript is byte-identical, so
    /// a combiner that ignored the secret and hashed the ciphertexts alone would return the same key.
    /// </summary>
    [Fact]
    public void ChangingTheRsaSecretChangesTheDataKey()
    {
        byte[] baseline = Combine();

        Assert.NotEqual(baseline, Combine(rsaSecret: FormatTestData.WithFlippedBit(RsaSecret(), 0)));
        Assert.NotEqual(baseline, Combine(rsaSecret: FormatTestData.WithFlippedBit(RsaSecret(), 255)));
        Assert.NotEqual(baseline, Combine(rsaSecret: KemSecret()));
    }

    /// <summary>
    /// <b>The ML-KEM secret contributes.</b> The mirror of the test above, and the one whose end-to-end
    /// counterpart is a wrong ML-KEM private key: implicit rejection means such a key yields a different
    /// secret against an unchanged ciphertext, which is exactly this comparison.
    /// </summary>
    [Fact]
    public void ChangingTheMLKemSecretChangesTheDataKey()
    {
        byte[] baseline = Combine();

        Assert.NotEqual(baseline, Combine(kemSecret: FormatTestData.WithFlippedBit(KemSecret(), 0)));
        Assert.NotEqual(baseline, Combine(kemSecret: FormatTestData.WithFlippedBit(KemSecret(), 255)));
        Assert.NotEqual(baseline, Combine(kemSecret: RsaSecret()));
    }

    /// <summary>
    /// Both ciphertexts contribute too — that is the transcript binding of §3.5.2, which is what stops
    /// either ciphertext being swapped or spliced in from another container without changing the key.
    /// </summary>
    [Fact]
    public void ChangingEitherCiphertextChangesTheDataKey()
    {
        byte[] baseline = Combine();

        Assert.NotEqual(baseline, Combine(wrappedSecret: FormatTestData.WithFlippedBit(WrappedSecret(), 0)));
        Assert.NotEqual(
            baseline, Combine(wrappedSecret: FormatTestData.WithFlippedBit(WrappedSecret(), (256 * 8) - 1)));
        Assert.NotEqual(baseline, Combine(encapsulation: FormatTestData.WithFlippedBit(Encapsulation(), 0)));
        Assert.NotEqual(
            baseline, Combine(encapsulation: FormatTestData.WithFlippedBit(Encapsulation(), (768 * 8) - 1)));
    }

    /// <summary>
    /// Swapping the two secrets with each other changes the key. Were the two branches not
    /// domain-separated, and were the combiner symmetric in its two secrets, this would return the same
    /// value — so it is the second assertion the differing labels are responsible for.
    /// </summary>
    [Fact]
    public void SwappingTheTwoSecretsChangesTheDataKey() =>
        Assert.NotEqual(Combine(), Combine(rsaSecret: KemSecret(), kemSecret: RsaSecret()));

    // --- The degenerate case the labels exist for -----------------------------------------------

    /// <summary>
    /// <b>Two equal secrets must not cancel.</b> With one shared label the two branches would be
    /// identical and their XOR would be 32 zero bytes — a data key anyone could guess, in a container that
    /// looks properly encrypted. A hostile sender can arrange it: it encapsulates first, sees the ML-KEM
    /// secret, and then chooses what to wrap under RSA. §3.5.2 names this as the reason the two labels
    /// differ, and this is the test that holds the reason to account.
    /// </summary>
    [Fact]
    public void TwoEqualSecretsDoNotCancelToAnAllZeroDataKey()
    {
        byte[] shared = FormatTestData.Sequence(0x5A, 32);

        byte[] dataKey = HybridKeyCombiner.Combine(
            FormatTestData.HmacSha256(), shared, (byte[])shared.Clone(), WrappedSecret(), Encapsulation());

        Assert.Equal(DataEncryptionDefaults.DataKeySizeBytes, dataKey.Length);
        Assert.NotEqual(new byte[DataEncryptionDefaults.DataKeySizeBytes], dataKey);
        Assert.Contains(dataKey, value => value != 0x00);

        // And it is still the value the specification prescribes.
        Assert.Equal(
            GoldenVectorPrimitives.HybridDataKey(
                shared, (byte[])shared.Clone(), WrappedSecret(), Encapsulation()),
            dataKey);
    }

    /// <summary>
    /// All-zero secrets are not a special case either — HMAC accepts a zero key, so the result is an
    /// ordinary pseudorandom value rather than something degenerate.
    /// </summary>
    [Fact]
    public void AllZeroSecretsStillProduceANonZeroDataKey()
    {
        byte[] dataKey = Combine(rsaSecret: new byte[32], kemSecret: new byte[32]);

        Assert.NotEqual(new byte[DataEncryptionDefaults.DataKeySizeBytes], dataKey);
    }

    // --- The transcript -------------------------------------------------------------------------

    /// <summary>
    /// The transcript is length-prefixed, so a re-split of the same concatenated bytes across the two
    /// fields is a <i>different</i> transcript. Without the lengths, a 4-byte and a 3-byte field would
    /// concatenate to the same seven bytes as a 3-byte and a 4-byte one.
    /// </summary>
    [Fact]
    public void TheTranscriptDistinguishesAReSplitOfTheSameBytes()
    {
        byte[] first = HybridKeyCombiner.BuildTranscript([0x01, 0x02, 0x03, 0x04], [0x05, 0x06, 0x07]);
        byte[] second = HybridKeyCombiner.BuildTranscript([0x01, 0x02, 0x03], [0x04, 0x05, 0x06, 0x07]);

        Assert.NotEqual(first, second);
        Assert.Equal(first.Length, second.Length);

        // …and therefore so are the data keys, with the secrets held fixed.
        Assert.NotEqual(
            Combine(wrappedSecret: [0x01, 0x02, 0x03, 0x04], encapsulation: [0x05, 0x06, 0x07]),
            Combine(wrappedSecret: [0x01, 0x02, 0x03], encapsulation: [0x04, 0x05, 0x06, 0x07]));
    }

    [Fact]
    public void TheTranscriptIsTheTwoLengthPrefixedCiphertexts()
    {
        byte[] transcript = HybridKeyCombiner.BuildTranscript(WrappedSecret(), Encapsulation());

        Assert.Equal(4 + 256 + 4 + 768, transcript.Length);
        Assert.Equal<byte[]>([0x00, 0x01, 0x00, 0x00], transcript[..4]);          // 256, little-endian
        Assert.Equal(WrappedSecret(), transcript[4..260]);
        Assert.Equal<byte[]>([0x00, 0x03, 0x00, 0x00], transcript[260..264]);     // 768, little-endian
        Assert.Equal(Encapsulation(), transcript[264..]);
    }

    /// <summary>
    /// The combiner never mutates its inputs. It is handed the very arrays the service will clear in its
    /// <c>finally</c>, so clearing them early — or writing into a caller's ciphertext buffer — would be a
    /// use-after-free in all but name.
    /// </summary>
    [Fact]
    public void TheCombinerLeavesItsInputsUntouched()
    {
        byte[] rsaSecret = RsaSecret();
        byte[] kemSecret = KemSecret();
        byte[] wrappedSecret = WrappedSecret();
        byte[] encapsulation = Encapsulation();

        HybridKeyCombiner.Combine(
            FormatTestData.HmacSha256(), rsaSecret, kemSecret, wrappedSecret, encapsulation);

        Assert.Equal(RsaSecret(), rsaSecret);
        Assert.Equal(KemSecret(), kemSecret);
        Assert.Equal(WrappedSecret(), wrappedSecret);
        Assert.Equal(Encapsulation(), encapsulation);
    }

    private static byte[] Fill(byte value)
    {
        byte[] bytes = new byte[DataEncryptionDefaults.DataKeySizeBytes];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = value;
        return bytes;
    }
}
