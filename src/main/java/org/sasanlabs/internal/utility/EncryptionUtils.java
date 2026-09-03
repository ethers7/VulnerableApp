package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
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

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** AES-GCM is an authenticated cipher mode: it provides confidentiality and integrity. */
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";

    /** Recommended GCM nonce length. A fresh random nonce is generated for every encryption. */
    private static final int GCM_NONCE_LENGTH_BYTES = 12;

    private static final int GCM_TAG_LENGTH_BITS = 128;

    private static final byte[] salt = new byte[16];

    static {
        SECURE_RANDOM.nextBytes(salt);
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

    /**
     * Encrypts the given plaintext with AES-GCM, which also authenticates the ciphertext.
     *
     * <p>A random nonce is generated for every invocation and is prefixed to the ciphertext.
     *
     * @param plaintext text to encrypt
     * @param key AES key, see {@link #getKeyFromPassword(String)}
     * @return Base64 of the nonce, the ciphertext and the authentication tag
     */
    public static String encrypt(String plaintext, SecretKey key) throws EncryptionException {
        try {
            byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(nonce);

            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] nonceAndCiphertext = new byte[nonce.length + encrypted.length];
            System.arraycopy(nonce, 0, nonceAndCiphertext, 0, nonce.length);
            System.arraycopy(encrypted, 0, nonceAndCiphertext, nonce.length, encrypted.length);
            return Base64.getEncoder().encodeToString(nonceAndCiphertext);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException("The provided key is invalid for AES encryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(
                    "AES encryption failed due to block size or padding issues", e);
        }
    }

    /**
     * Decrypts a value produced by {@link #encrypt(String, SecretKey)}.
     *
     * <p>AES-GCM verifies the tag, so decryption fails on a wrong key or tampered ciphertext.
     *
     * @param nonceAndCiphertextBase64 value produced by {@link #encrypt(String, SecretKey)}
     * @param key AES key used for the encryption
     * @return the recovered plaintext
     */
    public static String decrypt(String nonceAndCiphertextBase64, SecretKey key)
            throws EncryptionException {
        if (nonceAndCiphertextBase64 == null) {
            throw new EncryptionException("Ciphertext cannot be null ");
        }

        byte[] nonceAndCiphertext;
        try {
            nonceAndCiphertext = Base64.getDecoder().decode(nonceAndCiphertextBase64);
        } catch (IllegalArgumentException e) {
            throw new EncryptionException("Ciphertext is not valid Base64", e);
        }
        if (nonceAndCiphertext.length <= GCM_NONCE_LENGTH_BYTES) {
            throw new EncryptionException("Ciphertext is too short to hold a nonce and a tag");
        }

        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(
                            GCM_TAG_LENGTH_BITS, nonceAndCiphertext, 0, GCM_NONCE_LENGTH_BYTES));

            byte[] decrypted =
                    cipher.doFinal(
                            nonceAndCiphertext,
                            GCM_NONCE_LENGTH_BYTES,
                            nonceAndCiphertext.length - GCM_NONCE_LENGTH_BYTES);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException("The provided key is invalid for AES decryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(
                    "AES decryption failed: wrong key or the ciphertext was tampered with", e);
        }
    }

    /**
     * Checks whether the ciphertext decrypts, with the given key, to the expected plaintext.
     *
     * <p>Returns {@code false} instead of throwing when the key is wrong or the value is invalid.
     *
     * @param expectedPlaintext plaintext the ciphertext is expected to contain
     * @param nonceAndCiphertextBase64 value produced by {@link #encrypt(String, SecretKey)}
     * @param key AES key to attempt the decryption with
     */
    public static boolean decryptsTo(
            String expectedPlaintext, String nonceAndCiphertextBase64, SecretKey key) {
        if (expectedPlaintext == null) {
            return false;
        }
        try {
            // Constant time comparison, the compared values are secrets.
            return MessageDigest.isEqual(
                    decrypt(nonceAndCiphertextBase64, key).getBytes(StandardCharsets.UTF_8),
                    expectedPlaintext.getBytes(StandardCharsets.UTF_8));
        } catch (EncryptionException e) {
            return false;
        }
    }
}
