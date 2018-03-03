package com.serhii.cryptobook.project.service.impl;

import com.serhii.cryptobook.project.service.ServiceCrypto;
import com.serhii.cryptobook.project.service.ServiceKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class DefaultServiceCrypto implements ServiceCrypto {

    @Override
    public byte[] encryptWithCipher(byte[] data, Key key, String alg, int mode) {
        byte[] encryptData = null;
        try {
            Cipher cipher = Cipher.getInstance(alg);
            cipher.init(mode, key);
            encryptData = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return encryptData;
    }
}
