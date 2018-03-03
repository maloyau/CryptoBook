package com.serhii.cryptobook.project.service.impl;

import java.security.KeyPair;

public class Rsa1024ServiceKey extends DefaultServiceKey {

    private final static String ALGORYTHM = "RSA";
    private final static int KEYSIZE = 1024;

    public KeyPair generateKeyPair() {
        return super.generateKeyPair(ALGORYTHM, KEYSIZE);
    }
}
