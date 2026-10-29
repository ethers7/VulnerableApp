package org.sasanlabs.internal.utility;

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

    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

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

    /**
     * Encrypts using AES-GCM with a fresh random IV per message. The returned value is the Base64
     * encoding of {@code IV || ciphertext || authentication tag}.
     */
    public static String encrypt(String plaintext, SecretKey key) throws EncryptionException {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] payload = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
            return java.util.Base64.getEncoder().encodeToString(payload);

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
     * @throws EncryptionException if the input is malformed or the key/authentication tag does not
     *     match
     */
    public static String decrypt(String ciphertext, SecretKey key) throws EncryptionException {
        try {
            byte[] payload = java.util.Base64.getDecoder().decode(ciphertext);
            if (payload.length < GCM_IV_LENGTH_BYTES + GCM_TAG_LENGTH_BITS / 8) {
                throw new EncryptionException("Ciphertext is too short");
            }

            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload, 0, GCM_IV_LENGTH_BYTES));

            byte[] decrypted =
                    cipher.doFinal(
                            payload, GCM_IV_LENGTH_BYTES, payload.length - GCM_IV_LENGTH_BYTES);
            return new String(decrypted, StandardCharsets.UTF_8);

        } catch (IllegalArgumentException e) {
            throw new EncryptionException("Ciphertext is not valid Base64", e);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new EncryptionException("AES configuration not found ", e);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException("The provided key is invalid for AES decryption", e);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("AES decryption failed", e);
        }
    }
}
