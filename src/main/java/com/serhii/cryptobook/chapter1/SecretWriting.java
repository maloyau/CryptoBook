package com.serhii.cryptobook.chapter1;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.*;
import java.security.Key;
import java.security.SecureRandom;

public class SecretWriting {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: SecretWriting -d|-e text");
            return;
        }
        Key key;
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream("SecretKey.ser"));
            key = (Key) objectInputStream.readObject();
            objectInputStream.close();
        } catch (FileNotFoundException e) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            keyGenerator.init(new SecureRandom());
            key = keyGenerator.generateKey();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("SecretKey.ser"));
            objectOutputStream.writeObject(key);
            objectOutputStream.close();
        }
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        if (args[0].contains("e")) {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            String inputString = args[1];
            for (int i = 2; i < args.length; i++ ) {
                inputString += " " + args[i];
            }
            byte[] inputChars = inputString.getBytes("UTF-8");
            byte[] encodeChars = cipher.doFinal(inputChars);
            BASE64Encoder base64Encoder = new BASE64Encoder();
            String encodeString = base64Encoder.encode(encodeChars);
            System.out.println(encodeString);
        } else if (args[0].contains("d")) {
            cipher.init(Cipher.DECRYPT_MODE, key);
            BASE64Decoder base64Decoder = new BASE64Decoder();
            byte[] encodeChars = base64Decoder.decodeBuffer(args[1]);
            byte[] decodeChars = cipher.doFinal(encodeChars);
            String decodeString = new String(decodeChars, "UTF-8");
            System.out.println(decodeString);
        }
    }
}
