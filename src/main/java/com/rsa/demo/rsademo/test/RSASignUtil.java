package com.rsa.demo.rsademo.test;

import java.util.Base64;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.X509Certificate;

public class RSASignUtil {
    private static final String charset = "UTF-8";
    private static final String signType = "spay";

    /**
     * 生成签名
     *
     * @param plainText
     * @param privateKey
     * @return
     */
    public static String sign(PrivateKey privateKey, String plainText) {

        try {
            Signature signature = getSignatureObj(signType);
            signature.initSign(privateKey);//public final void initSign(PrivateKey privateKey)
            signature.update(plainText.getBytes(charset));
            byte[] signData = signature.sign();
            //return new String(Base64.encode(signData));
            return Base64.getEncoder().encodeToString(signData);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 通过PublicKey来验签
     *
     * @param publicKey
     * @param plainText
     * @param signature
     * @return
     * @throws Exception
     */
    public static boolean verifySign(PublicKey publicKey, String plainText, String signature) throws Exception {
        byte[] signData = Base64.getDecoder().decode(signature.getBytes(charset));

        try {
            Signature sig = getSignatureObj(signType);
            sig.initVerify(publicKey);//public final void initVerify(PublicKey publicKey)
            sig.update(plainText.getBytes(charset));
            return sig.verify(signData);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 通过公钥X509证书来验签
     *
     * @param cert
     * @param plainText
     * @param signature
     * @return
     * @throws Exception
     */
    public static boolean verifySign(X509Certificate cert, String plainText, String signature) throws Exception {
        byte[] signData = Base64.getDecoder().decode(signature.getBytes(charset));

        try {
            Signature sig = getSignatureObj(signType);
            sig.initVerify(cert);//public final void initVerify(Certificate certificate)
            sig.update(plainText.getBytes(charset));
            return sig.verify(signData);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return false;
    }

    private static Signature getSignatureObj(String signType) {
        String shaAlgorithm = null;
        if ("rest".equals(signType)) {
            shaAlgorithm = "SHA256withRSA";
        } else if ("spay".equals(signType)) {
            shaAlgorithm = "SHA1withRSA";
        }

        try {
            return Signature.getInstance(shaAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}