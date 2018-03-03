package com.serhii.cryptobook.project.service.impl;

import java.security.Key;

public class Des56ServiceKey extends DefaultServiceKey {

    private final static String ALGORYTHM = "DES";
    private final static int KEYSIZE = 56;

    public Key generateSecretKey() {
        return super.generateSecretKey(ALGORYTHM, KEYSIZE);
    }
}
