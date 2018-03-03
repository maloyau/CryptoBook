package com.serhii.cryptobook;

import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class IbmDevOps {

    private static String plainText = "Hello world!!!";

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, SignatureException {
        System.out.println("Original text: " + plainText);
        System.out.println("1. Message digest: " + new String(messageDigest(plainText, "MD5"), "UTF-8"));
        System.out.println("2. HMAC: " + new String(hmac(plainText, "HmacMD5"), "UTF-8"));
        System.out.println("3. Symetric:");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        Key key = keyGenerator.generateKey();

        byte[] cipherText = cryptoWithSecretKey(plainText.getBytes("UTF-8"), key, Cipher.ENCRYPT_MODE);
        System.out.println("    - Encrypt: " + new String(cipherText, "UTF-8"));
        System.out.println("    - Decrypt: " + new String(cryptoWithSecretKey(cipherText, key, Cipher.DECRYPT_MODE), "UTF-8"));
        System.out.println("4. Asymetric:");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        byte[] cipherText1 = encryptWithPublicKeyDecryptWithPrivateKey(plainText.getBytes("UTF-8"), keyPair.getPublic(), Cipher.ENCRYPT_MODE);
        System.out.println("    - Encrypt: " + new String(cipherText1, "UTF-8"));
        System.out.println("    - Decrypt: " + new String(encryptWithPublicKeyDecryptWithPrivateKey(cipherText1, keyPair.getPrivate(), Cipher.DECRYPT_MODE)));
        System.out.println("5. Signature:");
        KeyPairGenerator keyPairGenerator1 = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator1.initialize(1024);
        KeyPair keyPair1 = keyPairGenerator1.generateKeyPair();
        byte[] sign = sign(plainText.getBytes("UTF-8"), keyPair1.getPrivate());
        System.out.println("    - Signature: " + new String(sign, "UTF-8"));
        verifySign(plainText.getBytes("UTF-8"), sign, keyPair1.getPublic());
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance("MD5WithRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifySign(byte[] data, byte[] sign, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance("MD5WithRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        if (signature.verify(sign)) {
            System.out.println("    - Signature verified!");
            return true;
        } else {
            System.out.println("    - Signature failed!");
            return false;
        }
    }

    public static byte[] encryptWithPublicKeyDecryptWithPrivateKey(byte[] data, Key key, int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(mode, key);
        return cipher.doFinal(data);
    }

    public static byte[] cryptoWithSecretKey(byte[] data, Key key, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(mode, key);
        return cipher.doFinal(data);
    }

    public static byte[] messageDigest(String plainText, String algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(plainText.getBytes("UTF-8"));
        return messageDigest.digest();
    }

    public static byte[] hmac(String plainText, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        SecretKey secretKey = keyGenerator.generateKey();
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKey);
        mac.update(plainText.getBytes("UTF-8"));
        return mac.doFinal();
    }
}
