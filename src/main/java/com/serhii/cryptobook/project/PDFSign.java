package com.serhii.cryptobook.project;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.System;
import java.security.cert.Certificate;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PDFSign {
    public static void main(String[] args)
    {
        PdfReader reader;
        PdfSignatureAppearance sap;
        PdfStamper stp;
        FileOutputStream fout;
        PrivateKey key;
        PrivateKeySignature es;
        ExternalDigest digest;
        String hashName;

        Certificate[] chain;
        KeyStore ks;

        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch(Exception e) {
            System.out.print("Error adding security provider BouncyCastle: " + e + "\n");
            System.exit(1); return;
        }

        try {
            ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(new FileInputStream(args[0]), args[1].toCharArray());
        } catch(Exception e) {
            System.out.print("Error loading certificate store: " + e + "\n");
            System.exit(1); return;
        }

        try {
            String alias = (String)ks.aliases().nextElement();
            key = (PrivateKey)ks.getKey(alias, args[1].toCharArray());
            chain = ks.getCertificateChain(alias);
        } catch(Exception e) {
            System.out.print("Problems loading key or chain: " + e + "\n");
            System.exit(1); return;
        }

        if (key == null) {
            System.out.print("Failed to get key from the keystore: no keys found\n");
            System.exit(1); return;
        }

        //System.out.print("key uses algorithm " + key.getAlgorithm() + "\n");

        if (chain == null) {
            System.out.print("Failed to get certificate chain from the keystore: no certificates found\n");
            System.exit(1); return;
        }

        try {
            reader = new PdfReader(args[3]);
        } catch(Exception e) {
            System.out.print("Problems initializing PDF reader: " + e + "\n");
            System.exit(1); return;
        }

        try {
            fout = new FileOutputStream(args[4]);
        } catch(Exception e) {
            System.out.print("Failed to create file " + args[4] + ": " + e + "\n");
            System.exit(1); return;
        }

        try {
//  stp = PdfStamper.createSignature(reader, fout, '\0', new File("/tmp"));
            stp = PdfStamper.createSignature(reader, fout, '\0'); // in-memory processing
            sap = stp.getSignatureAppearance();
        } catch(Exception e) {
            System.out.print("Problems creating signature: " + e + "\n");
            System.exit(1); return;
        }

        try {
            es = new PrivateKeySignature(key, args[2], "BC");
            // workaround itextpdf-5.5.9 bug
            es.setEncryptionAlgorithm(key.getAlgorithm());
        }
        catch(Exception e)
        {
            System.out.print("Problems creating PrivateKeySignature: " + e + "\n");
            System.exit(1); return;
        }
        if (es == null) {
            System.out.print("Problems creating PrivateKeySignature: null\n");
            System.exit(1); return;
        }

        if (es.getHashAlgorithm() == null) {
            System.out.print("No usable hash algorithm found\n");
            System.exit(1); return;
        }

        try {
            digest = new BouncyCastleDigest();
        } catch(Exception e) {
            System.out.print("Problems creating BouncyCastleDigest: " + e + "\n");
            System.exit(1); return;
        }

        try {
            sap.setReason(args[5]);
            sap.setLocation(args[6]);
            sap.setContact(args[7]);
            sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
        } catch(Exception e) {
            System.out.print("Problem setting settings: " + e + "\n");
            System.exit(1); return;
        }

        try {
            MakeSignature.signDetached(sap, digest, es, chain, null, null, null, 0, CryptoStandard.CMS);
        } catch(Exception e) {
            System.out.print("Problem signing: " + e + "\n");
            System.exit(1); return;
        }

        try {
            stp.close();
        } catch(Exception e) {
            System.out.print("Problem closing: " + e + "\n");
            System.exit(1); return;
        }
        System.out.print("Done.\n");
    }
}
