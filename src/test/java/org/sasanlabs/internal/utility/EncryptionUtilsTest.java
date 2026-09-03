package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.sasanlabs.internal.utility.exception.EncryptionException;

class EncryptionUtilsTest {

    @Test
    @DisplayName("Caesar Cipher: Should shift characters by 3 and wrap around the alphabet")
    void caesarCipher_CorrectShift() throws EncryptionException {
        // Basic shift
        assertEquals("def", EncryptionUtils.caesarCipher("abc", 3));

        // Wrapping shift (z -> c)
        assertEquals("abc", EncryptionUtils.caesarCipher("xyz", 3));

        // Case preservation
        assertEquals("Abc", EncryptionUtils.caesarCipher("Xyz", 3));

        // Non-alphabetic characters remain unchanged
        assertEquals("123! @#", EncryptionUtils.caesarCipher("123! @#", 3));
    }

    @Test
    @DisplayName(
            "Custom Cipher: Should reverse the string and return a valid Base64 encoded string")
    void customCipher_ReverseAndBase64() throws EncryptionException {
        String input = "password";
        String reversed = "drowssap";
        String expectedBase64 = EncodingUtils.encodeBase64(reversed);

        assertEquals(expectedBase64, EncryptionUtils.customCipher(input));
    }

    @Test
    @DisplayName("Key Generation: Should derive an AES key from a string password")
    void getKeyFromPassword_ValidKey() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("my-secret-password");

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        // PBKDF2 output was configured for 128 bits (16 bytes)
        assertEquals(16, key.getEncoded().length);
    }

    @Test
    @DisplayName("AES-GCM Encryption: Should produce different ciphertext each time (random IV)")
    void encrypt_GcmNonDeterminism() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // In GCM mode with random IV, the same plaintext produces different ciphertext
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify it is valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));
    }

    @Test
    @DisplayName("AES-GCM Encryption: Ciphertext should include 12-byte IV prefix")
    void encrypt_GcmIncludesIvPrefix() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("test-key");
        String plaintext = "hello";

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // GCM output = 12 bytes IV + plaintext length + 16 bytes auth tag
        int expectedMinLength = 12 + plaintext.length() + 16;
        assertTrue(
                decoded.length >= expectedMinLength,
                "Ciphertext should contain IV + encrypted data + auth tag");
    }

    @Test
    @DisplayName("AES-GCM: Decrypt should recover original plaintext")
    void decrypt_GcmRoundTrip() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("round-trip-key");
        String plaintext = "This is a secret message for round-trip testing";

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        String decrypted = EncryptionUtils.decrypt(ciphertext, key);

        assertEquals(plaintext, decrypted);
    }

    @Test
    @DisplayName("AES-GCM: Decrypt with wrong key should throw EncryptionException")
    void decrypt_GcmWrongKeyFails() throws EncryptionException {
        SecretKey encryptKey = EncryptionUtils.getKeyFromPassword("correct-key");
        SecretKey wrongKey = EncryptionUtils.getKeyFromPassword("wrong-key");
        String plaintext = "sensitive data";

        String ciphertext = EncryptionUtils.encrypt(plaintext, encryptKey);

        assertThrows(
                EncryptionException.class, () -> EncryptionUtils.decrypt(ciphertext, wrongKey));
    }
}
