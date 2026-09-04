package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Comparison helper for values whose content must not leak through a timing side channel, such as
 * password hashes, message authentication codes, JWT signatures and symmetric keys.
 *
 * <p>{@link String#equals(Object)} returns as soon as it reaches the first differing character, so
 * the time it takes tells an attacker how many leading characters were guessed correctly. Repeating
 * that measurement recovers the expected value one character at a time. {@link
 * MessageDigest#isEqual(byte[], byte[])} always inspects every byte, which is the same primitive
 * {@code EncryptionUtils.isMatchingPlaintext} already relies on.
 *
 * @see <a href="https://cwe.mitre.org/data/definitions/208.html">CWE-208: Observable Timing
 *     Discrepancy</a>
 */
public final class SecretComparisonUtils {

    private SecretComparisonUtils() {}

    /**
     * Compares two secrets without leaking, through the time taken, where they start to differ.
     * Only the length of {@code left} is observable.
     *
     * <p>The outcome matches {@link String#equals(Object)} for the values this application
     * compares: two {@code null} references are equal, a {@code null} is never equal to a value,
     * and otherwise the UTF-8 encodings have to match byte for byte.
     */
    public static boolean isEqual(String left, String right) {
        if (left == null || right == null) {
            return left == null && right == null;
        }
        return MessageDigest.isEqual(
                left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }
}
