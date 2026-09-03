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
    @DisplayName("AES Encryption: Should produce different ciphertext each time (GCM Mode Property)")
    void encrypt_GcmNonDeterminism() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // In GCM mode, the same plaintext with the same key produces different ciphertext
        // due to random IV, which prevents pattern analysis
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify both are valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext2));
    }

    @Test
    @DisplayName(
            "AES Encryption: Identical blocks should NOT produce identical ciphertext blocks (GCM Security)")
    void encrypt_GcmNoPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("vulnerability-test");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // GCM mode prepends a 12-byte IV, skip it to get the actual ciphertext
        int ivLength = 12;
        assertTrue(decoded.length > ivLength + 32, "Ciphertext should contain IV and encrypted data");

        // Split the encrypted portion into two 16-byte segments
        byte[] block1 = new byte[16];
        byte[] block2 = new byte[16];
        System.arraycopy(decoded, ivLength, block1, 0, 16);
        System.arraycopy(decoded, ivLength + 16, block2, 0, 16);

        // GCM mode prevents pattern leakage: identical input blocks produce different output blocks
        assertFalse(
                java.util.Arrays.equals(block1, block2),
                "GCM mode should NOT leak identical blocks");
    }

    @Test
    @DisplayName("AES Decryption: Should correctly decrypt GCM encrypted data")
    void decrypt_GcmRoundTrip() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("test-password");
        String originalPlaintext = "This is a secret message to encrypt and decrypt";

        // Encrypt the plaintext
        String ciphertext = EncryptionUtils.encrypt(originalPlaintext, key);

        // Decrypt the ciphertext
        String decryptedPlaintext = EncryptionUtils.decrypt(ciphertext, key);

        // Verify round-trip encryption/decryption works
        assertEquals(originalPlaintext, decryptedPlaintext);
    }

    @Test
    @DisplayName("AES Decryption: Should fail with wrong key")
    void decrypt_WrongKey() throws EncryptionException {
        SecretKey correctKey = EncryptionUtils.getKeyFromPassword("correct-password");
        SecretKey wrongKey = EncryptionUtils.getKeyFromPassword("wrong-password");
        String plaintext = "Secret message";

        // Encrypt with correct key
        String ciphertext = EncryptionUtils.encrypt(plaintext, correctKey);

        // Attempting to decrypt with wrong key should throw EncryptionException
        assertThrows(
                EncryptionException.class,
                () -> EncryptionUtils.decrypt(ciphertext, wrongKey),
                "Decryption with wrong key should fail");
    }
}
