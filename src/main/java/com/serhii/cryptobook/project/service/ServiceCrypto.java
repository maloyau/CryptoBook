package com.serhii.cryptobook.project.service;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.Key;

public interface ServiceCrypto {
    byte[] encryptWithCipher(byte[] data, Key key, String alg, int mode) throws BadPaddingException, IllegalBlockSizeException;
}
