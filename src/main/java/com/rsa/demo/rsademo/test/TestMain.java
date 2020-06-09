package com.rsa.demo.rsademo.test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.UUID;

public class TestMain {

    private static final String charset = "UTF-8";

    public static final String publicKeyString =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvGGQDrUk7ejBfgR6cwDhTUqDe" +
                    "1+ooXzwowLfRRDqu1N0O9KyeAsY8nI8HUvzYGXODNMBEKZ2v8Ck7lelVoxlgkIAT" +
                    "GHB2nM+TBZOPQAdF0X4crJh1yWjdnrGO5fluqUalwRvYIG91mqIPnvSGL9mLDIhi" +
                    "7PR/duEe7KzwDCi3DQIDAQAB";
    public static final String privateKeyString =
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAK8YZAOtSTt6MF+B" +
                    "HpzAOFNSoN7X6ihfPCjAt9FEOq7U3Q70rJ4CxjycjwdS/NgZc4M0wEQpna/wKTuV" +
                    "6VWjGWCQgBMYcHacz5MFk49AB0XRfhysmHXJaN2esY7l+W6pRqXBG9ggb3Waog+e" +
                    "9IYv2YsMiGLs9H924R7srPAMKLcNAgMBAAECgYEAgzW85QB7K2XyT+87WG23B8GY" +
                    "qcWVRDGxrDxWwyvk6dS73xQ9Mp+TnCIaEHwA25Oe+0iRd8LT1t8alvtNAo6ZWYU9" +
                    "Ek0yuNTJ5YpWIal+A3c25Zm8Ir3CgkCvq7+q+4OOhC4rOMoY6G8rxQQ7fm4noW0A" +
                    "lZbgQJrhaqDfute4v2ECQQDVZZpZgNU7u9E2CoAXUjUMGWmapdyAsfdZo8kq7mP3" +
                    "g/4JdcGVykxP2YTI1rR2/6vPvnRZN8wcSNVRoM+qWTCFAkEA0g0/3m5TD6wR5ajj" +
                    "SoIMmYgu5OFToKVX1mDoPKBnrjsxzuPZHm/KhRtkRzafd+vs/DbLs60QtQTmyY7q" +
                    "BZm26QJBAMq5KgeLF4cWpupS0VrWUuS6o5MxrCdqadPzf6FUNQ2ni8cK4ivdsd9N" +
                    "ghKVvX0q59qEUN2M30+jdVuFjKKE9k0CQBtIHUOGkMM4Vhq+FMdYnMpUJcMUgQgc" +
                    "cYwmigNV0iGPDqkQbuLFIkinhh65uXyZ5+3aMBrmH4VjXZZQOZUAogECQHs7Ywr+" +
                    "ZSMllnuYOM9z+dXCcQRGKfcVa90fGo3bjrqanyhGyjAwwfECajPlTHm75AdgWegH" +
                    "XXWxFu93sms7KJY=";

    public static void main(String[] args) throws Exception {
        testCipher();
        // testSign();
    }

    public static void testCipher() throws Exception {
        String text = "abcd" + UUID.randomUUID();
//        Key publicKey = RSACertUtils.getPublicKey();
        PublicKey publicKey = RSACertUtils.getPublicKey(TestMain.publicKeyString);
        String encryptStr = RSACipherUtil.encrypt(publicKey, text, charset);
        System.out.println("encryptStr:" + encryptStr);

//        Key privateKey = RSACertUtils.getPrivateKey(merId);
        PrivateKey privateKey = RSACertUtils.getPrivateKey(TestMain.privateKeyString);
        String decryptStr = RSACipherUtil.decrypt(privateKey, encryptStr, charset);
        System.out.println("decryptStr:" + decryptStr);
        //公钥加密 私钥解密
        System.out.println(text.equals(decryptStr));
    }

    public static void testSign() throws Exception {
        System.out.println(publicKeyString);
        String text = "{\"trade_no\":\"1904261100329133\",\"amount\":\"1\",\"mer_id\":\"90000002\",\"mer_date\":\"20190426\",\"order_id\":\"0306262632992608256R\"}";
        PrivateKey privateKey = RSACertUtils.getPrivateKey(privateKeyString);
        String signature = RSASignUtil.sign(privateKey, text);
        System.out.println("signature:" + signature);

        PublicKey publicKey = RSACertUtils.getPublicKey(publicKeyString);

        assert signature != null;
        boolean verifiedOK = RSASignUtil.verifySign(publicKey, text, signature);
        System.out.println(verifiedOK);

    }

}
