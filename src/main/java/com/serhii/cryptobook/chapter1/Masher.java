package com.serhii.cryptobook.chapter1;

import sun.misc.BASE64Encoder;

import java.io.FileInputStream;
import java.security.MessageDigest;

public class Masher {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: Masher filename");
            return;
        }
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        FileInputStream fileInputStream = new FileInputStream(args[0]);
        byte[] buffer = new byte[8192];
        int length;
        while ((length = fileInputStream.read(buffer)) != -1)
            messageDigest.update(buffer, 0, length);
        byte[] raw = messageDigest.digest();
        BASE64Encoder base64Encoder = new BASE64Encoder();
        String base64 = base64Encoder.encode(raw);
        System.out.println(base64);
    }

}
