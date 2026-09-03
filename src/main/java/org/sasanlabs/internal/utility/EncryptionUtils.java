package org.sasanlabs.internal.utility;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.sasanlabs.internal.utility.exception.EncryptionException;

/** This class contains methods related to encryption. */
public class EncryptionUtils {

    private EncryptionUtils() {}

    /**
     * INSECURE: Caesar Cipher shifts alphabetic characters positions to the right overflowing to
     * the beginning of the alphabet. 'z' will shift to 'a' and so on.
     *
     * @param rawPassword plaintext password to encrypt
     * @param shift how many shifts right
     */
    public static String caesarCipher(String rawPassword, int shift) throws EncryptionException {

        if (rawPassword == null) {
            throw new EncryptionException("Raw password cannot be null ");
        }

        // Technically shift can be any non-zero integer, for clarity it should be between 0-25
        // inclusive
        if (shift < 0 || shift >= 26) {
            throw new EncryptionException("Shift value must be between 0 and 25 inclusive.");
        }

        StringBuilder builder = new StringBuilder();
        for (char ch : rawPassword.toCharArray()) {
            if (Character.isLetter(ch)) {
                char base = Character.isUpperCase(ch) ? 'A' : 'a';
                builder.append((char) ((ch - base + shift) % 26 + base));
            } else {
                builder.append(ch);
            }
        }
        return builder.toString();
    }

    /**
     * INSECURE: Custom cipher that obscures the texts by reversing it then Base64 encodes it.
     *
     * @param rawPassword password to encrypt
     */
    public static String customCipher(String rawPassword) throws EncryptionException {
        if (rawPassword == null) {
            throw new EncryptionException("Raw password cannot be null ");
        }
        String reversed = new StringBuilder(rawPassword).reverse().toString();
        return EncodingUtils.encodeBase64(reversed);
    }

    private static final byte[] salt = new byte[16];

    static {
        new SecureRandom().nextBytes(salt);
    }

    public static SecretKey getKeyFromPassword(String password) throws EncryptionException {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1, 128);

            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Error generating AES key from password", e);
        }
    }

    public static String encrypt(String plaintext, SecretKey key) throws EncryptionException {
        try {
            // Use AES/GCM mode with authenticated encryption (CWE-327 remediation)
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            // Generate a random 12-byte IV for GCM mode
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);

            // GCM authentication tag length is 128 bits
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Prepend IV to ciphertext for later decryption
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encrypted.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);

            return java.util.Base64.getEncoder().encodeToString(byteBuffer.array());

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("The provided key is invalid for AES encryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(
                    "AES encryption failed due to block size or padding issues", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException("Invalid GCM parameters", e);
        }
    }

    public static String decrypt(String ciphertext, SecretKey key) throws EncryptionException {
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(ciphertext);

            // Extract IV from the beginning of the ciphertext
            ByteBuffer byteBuffer = ByteBuffer.wrap(decoded);
            byte[] iv = new byte[12];
            byteBuffer.get(iv);

            byte[] encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            // Use AES/GCM mode for decryption
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException e) {
            throw new EncryptionException("The provided key is invalid for AES decryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(
                    "AES decryption failed - invalid ciphertext or wrong key", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new EncryptionException("Invalid GCM parameters", e);
        } catch (IllegalArgumentException e) {
            throw new EncryptionException("Invalid Base64 ciphertext", e);
        }
    }
}
