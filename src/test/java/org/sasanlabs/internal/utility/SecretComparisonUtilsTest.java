package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests for {@link SecretComparisonUtils}. */
class SecretComparisonUtilsTest {

    private static final String SECRET = "d0c3d5b7f1a24c9e8b6a0f5e4d3c2b1a";

    @Test
    @DisplayName("Should accept the correct value")
    void isEqual_AcceptsIdenticalValue() {
        assertTrue(SecretComparisonUtils.isEqual(SECRET, new String(SECRET.toCharArray())));
    }

    @Test
    @DisplayName("Should reject a value that only shares its prefix")
    void isEqual_RejectsSamePrefix() {
        String almostRight = SECRET.substring(0, SECRET.length() - 1) + "b";
        assertFalse(SecretComparisonUtils.isEqual(SECRET, almostRight));
    }

    @Test
    @DisplayName("Should reject values of a different length")
    void isEqual_RejectsDifferentLength() {
        assertFalse(SecretComparisonUtils.isEqual(SECRET, SECRET + "0"));
        assertFalse(SecretComparisonUtils.isEqual(SECRET, SECRET.substring(0, 4)));
        assertFalse(SecretComparisonUtils.isEqual(SECRET, ""));
    }

    @Test
    @DisplayName("Should be case sensitive, like String equality")
    void isEqual_IsCaseSensitive() {
        assertFalse(SecretComparisonUtils.isEqual(SECRET, SECRET.toUpperCase()));
    }

    @Test
    @DisplayName("Should compare values that need more than one byte per character")
    void isEqual_HandlesMultiByteCharacters() {
        // Built from a code point so that this test does not depend on the encoding this source
        // file is compiled with. 0xF6 is a lower case o with a diaeresis, two bytes in UTF-8.
        String multiByte = "passw" + (char) 0xF6 + "rd";
        assertTrue(SecretComparisonUtils.isEqual(multiByte, "passw" + (char) 0xF6 + "rd"));
        assertFalse(SecretComparisonUtils.isEqual(multiByte, "password"));
    }

    @Test
    @DisplayName("Should treat null like String equality does")
    void isEqual_NullHandling() {
        assertTrue(SecretComparisonUtils.isEqual(null, null));
        assertFalse(SecretComparisonUtils.isEqual(null, SECRET));
        assertFalse(SecretComparisonUtils.isEqual(SECRET, null));
    }
}
