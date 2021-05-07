package cpabe;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESCoder {
    private static byte[] getRawKey(byte[] seed) throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        kgen.init(128, sr); // 192 and 256 bits may not be available
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        return raw;
    }

    public static byte[] multiCrypt(byte[] seed, byte[] data, int mode) throws AESException {
        try {
            byte[] raw = getRawKey(seed);
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(mode, skeySpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new AESException(e.getMessage(), e.getCause());
        }
    }

    public static byte[] encrypt(byte[] seed, byte[] plaintext) throws AESException {
        return multiCrypt(seed, plaintext, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(byte[] seed, byte[] ciphertext) throws AESException {
        return multiCrypt(seed, ciphertext, Cipher.DECRYPT_MODE);
    }
}