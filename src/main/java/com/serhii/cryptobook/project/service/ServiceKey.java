package com.serhii.cryptobook.project.service;

import java.security.*;

public interface ServiceKey {

    Key generateSecretKey(String alg, int keysize);

    KeyPair generateKeyPair(String alg, int keysize);

    PrivateKey loadPrivateKeyFromFile();

    PublicKey loadPublicKeyFromFile();

    void savePrivateKeyFromFile();

    void savePublicKeyFromFile();

}

