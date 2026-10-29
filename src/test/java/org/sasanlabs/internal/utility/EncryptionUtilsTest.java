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
    @DisplayName("AES Encryption: Should produce randomized ciphertext (GCM with random IV)")
    void encrypt_RandomizedCiphertext() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // A random per-message IV means the same plaintext yields different ciphertexts
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify it is valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));
    }

    @Test
    @DisplayName("AES Encryption: Identical blocks should not produce identical ciphertext blocks")
    void encrypt_NoPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("vulnerability-test");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // Layout is IV (12 bytes) || ciphertext || tag; skip the IV and compare ciphertext blocks
        byte[] block1 = new byte[16];
        byte[] block2 = new byte[16];
        System.arraycopy(decoded, 12, block1, 0, 16);
        System.arraycopy(decoded, 28, block2, 0, 16);

        assertFalse(java.util.Arrays.equals(block1, block2), "Identical blocks must not leak");
    }

    @Test
    @DisplayName("AES Encryption: Decrypt should round-trip and reject wrong keys / tampering")
    void encryptDecrypt_RoundTripAndIntegrity() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("round-trip");
        String ciphertext = EncryptionUtils.encrypt("hello world", key);

        assertEquals("hello world", EncryptionUtils.decrypt(ciphertext, key));

        SecretKey otherKey = new javax.crypto.spec.SecretKeySpec(new byte[16], "AES");
        assertThrows(EncryptionException.class, () -> EncryptionUtils.decrypt(ciphertext, otherKey));

        byte[] tampered = Base64.getDecoder().decode(ciphertext);
        tampered[tampered.length - 1] ^= 0x01;
        String tamperedText = Base64.getEncoder().encodeToString(tampered);
        assertThrows(EncryptionException.class, () -> EncryptionUtils.decrypt(tamperedText, key));
    }
}
