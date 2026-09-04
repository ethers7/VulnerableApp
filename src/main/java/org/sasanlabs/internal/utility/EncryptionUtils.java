package org.sasanlabs.internal.utility;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
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

    /** AES in Galois/Counter Mode: authenticated encryption that never repeats a block. */
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";

    /** NIST SP 800-38D recommends a 96 bit IV and the full 128 bit authentication tag for GCM. */
    private static final int GCM_IV_LENGTH_BYTES = 12;

    private static final int GCM_TAG_LENGTH_BITS = 128;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

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
     * Encrypts the given plaintext with AES-GCM. A fresh random IV is generated for every
     * invocation and prefixed to the ciphertext, so the same plaintext never encrypts to the same
     * value and identical plaintext blocks do not leak.
     *
     * @param plaintext value to encrypt
     * @param key AES key, for example one built by {@link #getKeyFromPassword(String)}
     * @return Base64 of the IV followed by the ciphertext and its authentication tag
     */
    public static String encrypt(String plaintext, SecretKey key) throws EncryptionException {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] ivAndCiphertext = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
            System.arraycopy(encrypted, 0, ivAndCiphertext, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(ivAndCiphertext);

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
     * Decrypts a value produced by {@link #encrypt(String, SecretKey)}. GCM authenticates the
     * ciphertext, so a wrong key or tampered data fails loudly instead of returning garbage.
     *
     * @param ciphertext Base64 of the IV followed by the ciphertext and its authentication tag
     * @param key AES key the value was encrypted with
     */
    public static String decrypt(String ciphertext, SecretKey key) throws EncryptionException {
        try {
            byte[] raw = Base64.getDecoder().decode(ciphertext);
            if (raw.length <= GCM_IV_LENGTH_BYTES) {
                throw new EncryptionException("Ciphertext is too short to carry an AES-GCM IV");
            }
            byte[] iv = Arrays.copyOfRange(raw, 0, GCM_IV_LENGTH_BYTES);
            byte[] encrypted = Arrays.copyOfRange(raw, GCM_IV_LENGTH_BYTES, raw.length);

            Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) {
            throw new EncryptionException("Ciphertext is not a valid AES-GCM payload", e);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException("The provided key is invalid for AES decryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(
                    "AES decryption failed, the ciphertext could not be authenticated", e);
        }
    }

    /**
     * Constant time check whether {@code plaintext} is the value protected by {@code ciphertext}
     * under the given key. Returns {@code false} when the ciphertext does not authenticate with
     * that key, which is what happens for a wrong password.
     */
    public static boolean isMatchingPlaintext(String plaintext, String ciphertext, SecretKey key) {
        if (plaintext == null || ciphertext == null) {
            return false;
        }
        try {
            byte[] decrypted = decrypt(ciphertext, key).getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(decrypted, plaintext.getBytes(StandardCharsets.UTF_8));
        } catch (EncryptionException e) {
            return false;
        }
    }
}
