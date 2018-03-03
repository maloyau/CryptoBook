package com.serhii.cryptobook.project.service.impl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class Des56ServiceCrypto extends DefaultServiceCrypto {

    private final static String ALGORYTHM = "DES/ECB/PKCS5Padding";

    private Cipher cipher;

    public Des56ServiceCrypto() {
        try {
            this.cipher = Cipher.getInstance(ALGORYTHM);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(byte[] plainText, Key key) {
        byte[] cipherText = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(plainText);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText, Key key) {
        byte[] plainText = null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            plainText = cipher.doFinal(cipherText);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return plainText;
    }

}
