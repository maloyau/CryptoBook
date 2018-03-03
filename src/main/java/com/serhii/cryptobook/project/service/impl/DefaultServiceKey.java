package com.serhii.cryptobook.project.service.impl;

import com.serhii.cryptobook.project.service.ServiceKey;

import javax.crypto.KeyGenerator;
import java.security.*;

public class DefaultServiceKey implements ServiceKey {
    @Override
    public Key generateSecretKey(String alg, int keysize) {
        Key key = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(alg);
            keyGenerator.init(keysize);
            key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }

    @Override
    public KeyPair generateKeyPair(String alg, int keysize) {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(alg);
            keyPairGenerator.initialize(keysize);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    @Override
    public PrivateKey loadPrivateKeyFromFile() {
        return null;
    }

    @Override
    public PublicKey loadPublicKeyFromFile() {
        return null;
    }

    @Override
    public void savePrivateKeyFromFile() {

    }

    @Override
    public void savePublicKeyFromFile() {

    }
}
