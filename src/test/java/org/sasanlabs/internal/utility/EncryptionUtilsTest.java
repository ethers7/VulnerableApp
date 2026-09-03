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
    @DisplayName("AES-GCM Encryption: Should use a fresh random nonce for every encryption")
    void encrypt_RandomNoncePerInvocation() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("fixed-password");
        String plaintext = "This is a secret message that is exactly 32 bytes";

        String ciphertext1 = EncryptionUtils.encrypt(plaintext, key);
        String ciphertext2 = EncryptionUtils.encrypt(plaintext, key);

        // A random nonce per encryption means the same plaintext never encrypts to the same value
        assertNotEquals(ciphertext1, ciphertext2);

        // Verify it is valid Base64
        assertDoesNotThrow(() -> Base64.getDecoder().decode(ciphertext1));

        // Both ciphertexts still decrypt back to the original plaintext
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext1, key));
        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext2, key));
    }

    @Test
    @DisplayName("AES-GCM Encryption: Identical plaintext blocks must not leak in ciphertext")
    void encrypt_NoBlockPatternLeakage() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("no-pattern-leakage");

        // Create two identical 16-byte blocks (AES block size)
        String block = "identical-block-"; // 16 characters
        String plaintext = block + block;

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);
        byte[] decoded = Base64.getDecoder().decode(ciphertext);

        // Skip the 12 byte nonce prefix and split the ciphertext into two 16-byte segments
        byte[] block1 = new byte[16];
        byte[] block2 = new byte[16];
        System.arraycopy(decoded, 12, block1, 0, 16);
        System.arraycopy(decoded, 28, block2, 0, 16);

        assertFalse(
                Arrays.equals(block1, block2),
                "Identical plaintext blocks must not produce identical ciphertext blocks");
    }

    @Test
    @DisplayName("AES-GCM Decryption: Should round-trip the plaintext with the same key")
    void decrypt_RoundTrip() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("round-trip-password");
        String plaintext = "secret-value";

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);

        assertEquals(plaintext, EncryptionUtils.decrypt(ciphertext, key));
        assertTrue(EncryptionUtils.decryptsTo(plaintext, ciphertext, key));
    }

    @Test
    @DisplayName("AES-GCM Decryption: Should fail when the wrong key is used")
    void decrypt_WrongKeyFails() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("correct-password");
        SecretKey wrongKey = EncryptionUtils.getKeyFromPassword("wrong-password");
        String plaintext = "secret-value";

        String ciphertext = EncryptionUtils.encrypt(plaintext, key);

        assertThrows(
                EncryptionException.class, () -> EncryptionUtils.decrypt(ciphertext, wrongKey));
        assertFalse(EncryptionUtils.decryptsTo(plaintext, ciphertext, wrongKey));
    }

    @Test
    @DisplayName("AES-GCM Decryption: Should reject a tampered ciphertext (message integrity)")
    void decrypt_TamperedCiphertextRejected() throws EncryptionException {
        SecretKey key = EncryptionUtils.getKeyFromPassword("integrity-password");
        String plaintext = "secret-value";

        byte[] decoded = Base64.getDecoder().decode(EncryptionUtils.encrypt(plaintext, key));
        // Flip a bit in the last ciphertext byte, the authentication tag must catch it
        decoded[decoded.length - 1] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(decoded);

        assertThrows(EncryptionException.class, () -> EncryptionUtils.decrypt(tampered, key));
        assertFalse(EncryptionUtils.decryptsTo(plaintext, tampered, key));
    }
}
