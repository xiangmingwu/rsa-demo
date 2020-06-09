package com.rsa.demo.rsademo.test;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSACipherUtil {
    /**
     * 公钥加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public static String encrypt(PublicKey publicKey, String data, String charset) throws Exception {
        Cipher cipher = Cipher.getInstance(KeyFactory.getInstance("RSA").getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(data.getBytes(charset));

        byte[] encodedByte = Base64.getEncoder().encode(cipherText);
        return new String(encodedByte).replace("\n", "");
    }

    /**
     * RSA私钥解密
     *
     * @param privateKey
     * @param data
     * @return
     * @throws Exception
     */
    public static String decrypt(PrivateKey privateKey, String data, String charset) throws Exception {
        byte[] byteData = Base64.getDecoder().decode(data.getBytes(charset));

        Cipher cipher = Cipher.getInstance(KeyFactory.getInstance("RSA").getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] retB = cipher.doFinal(byteData);

        return new String(retB);
    }
}
