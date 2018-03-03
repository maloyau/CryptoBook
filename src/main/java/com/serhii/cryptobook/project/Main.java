package com.serhii.cryptobook.project;

import com.serhii.cryptobook.project.service.ServiceCrypto;
import com.serhii.cryptobook.project.service.ServiceKey;
import com.serhii.cryptobook.project.service.impl.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

    private static String plainText = "Hello World!!!";

    public static void main(String[] args) {
        System.out.println("Original text: " + plainText);
        // Des 56
        System.out.println("1. Symmetric Algorithm DES, key size - 56");
        Des56ServiceKey des56ServiceKey = new Des56ServiceKey();
        Des56ServiceCrypto des56ServiceCrypto = new Des56ServiceCrypto();
        Key secretKey = des56ServiceKey.generateSecretKey();
        byte[] cipherBytes = des56ServiceCrypto.encrypt(stringToBytesUTF8(plainText),secretKey);
        String cipherString = bytesToStringUTF8(cipherBytes);
        System.out.println("Encrypt text: " + cipherString);
        System.out.println("Decrypt text: " + bytesToStringUTF8(des56ServiceCrypto.decrypt(cipherBytes, secretKey)));
        // RSA 1024
        System.out.println("2. Asymmetric Algorithm RSA, key size - 1024");
        Rsa1024ServiceKey rsa1024ServiceKey = new Rsa1024ServiceKey();
        RsaMd5ServiceCrypto rsaMd5ServiceCrypto = new RsaMd5ServiceCrypto();
        KeyPair rsaKeyPair = rsa1024ServiceKey.generateKeyPair();
        PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
        PublicKey rsaPublicKey = rsaKeyPair.getPublic();
        byte[] cipherBytes1 = rsaMd5ServiceCrypto.encrypt(stringToBytesUTF8(plainText), rsaPublicKey);
        String cipherString1 = bytesToStringUTF8(cipherBytes1);
        System.out.println("Encrypt text: " + cipherString1);
        System.out.println("Decrypt text: " + bytesToStringUTF8(rsaMd5ServiceCrypto.decrypt(cipherBytes1, rsaPrivateKey)));
        /*
        ServiceCrypto serviceCrypto = new DefaultServiceCrypto();
        ServiceKey serviceKey = new DefaultServiceKey();
        byte[] plainTextByte = plainText.getBytes("UTF-8");
        Key key = serviceKey.generateSecretKey("DES", 56);
        byte[] encryptTextByte = serviceCrypto.encryptWithCipher(plainTextByte, key, "DES/ECB/PKCS5Padding", Cipher.ENCRYPT_MODE);
        String encryptText = new String(encryptTextByte, "UTF-8");
        System.out.println("1. Encrypt with secret key: " + encryptText);
        byte[] decryptTextByte = serviceCrypto.encryptWithCipher(encryptTextByte, key, "DES/ECB/PKCS5Padding", Cipher.DECRYPT_MODE);
        String decryptText = new String(decryptTextByte, "UTF-8");
        System.out.println("   Decrypt with secret key: " + decryptText); */
    }

    private static String bytesToStringUTF8(byte[] bytes) {
        String str = null;
        try {
            str = new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return str;
    }

    private static byte[] stringToBytesUTF8(String str) {
        byte[] bytes = null;
        try {
            bytes = str.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return bytes;
    }
}
