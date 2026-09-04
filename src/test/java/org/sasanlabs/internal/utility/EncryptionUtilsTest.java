package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
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
    @DisplayName("AES-GCM Encryption: Should never repeat ciphertext, and should round trip")
    void encrypt_RandomIvPerInvocation() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // A fresh random IV per message means the same plaintext never encrypts to the same value
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify it is valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));

        // Both still decrypt back to the original plaintext
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext1, key));
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext2, key));
    }

    @Test
    @DisplayName("AES-GCM Encryption: Identical plaintext blocks must not leak as equal blocks")
    void encrypt_NoPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("vulnerability-test");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        byte[] decoded = Base64.getDecoder().decode(EncryptionUtils.encrypt(plaintext, key));

        // Skip the 12 byte IV prefix, then compare the two 16 byte ciphertext blocks
        byte[] block1 = Arrays.copyOfRange(decoded, 12, 28);
        byte[] block2 = Arrays.copyOfRange(decoded, 28, 44);

        // A counter based, IV seeded keystream must not repeat for identical input blocks
        assertFalse(Arrays.equals(block1, block2), "Ciphertext leaked identical plaintext blocks");
    }

    @Test
    @DisplayName("AES-GCM Decryption: A wrong key must not authenticate the ciphertext")
    void decrypt_WrongKeyIsRejected() throws EncryptionException {
        String plaintext = "correct-horse-battery-staple";
        SecretKey rightKey = EncryptionUtils.getKeyFromPassword("right-password");
        SecretKey wrongKey = EncryptionUtils.getKeyFromPassword("wrong-password");

        String ciphertext = EncryptionUtils.encrypt(plaintext, rightKey);

        assertThrows(
                EncryptionException.class, () -> EncryptionUtils.decrypt(ciphertext, wrongKey));
        assertFalse(EncryptionUtils.isMatchingPlaintext(plaintext, ciphertext, wrongKey));
        assertTrue(EncryptionUtils.isMatchingPlaintext(plaintext, ciphertext, rightKey));
    }
}
