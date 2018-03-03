package com.serhii.cryptobook;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.DSTU4145PublicKey;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DSTU4145KeyPairGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.DSTU4145;
import org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.util.Collection;

import static org.bouncycastle.asn1.ua.UAObjectIdentifiers.*;

public class Dstu4145BouncyCastleExample {

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, IllegalAccessException, InstantiationException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSTU4145", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2.0");
        SecureRandom random = new SecureRandom();
        keyPairGenerator.initialize(ecGenParameterSpec, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        System.out.println(privateKey);
        System.out.println(publicKey);
/*
        ECKeyPairGenerator ecKeyPairGenerator = new ECKeyPairGenerator();
        ecKeyPairGenerator.init(new ECKeyGenerationParameters(DSTU4145NamedCurves.getByOID(new ASN1ObjectIdentifier("1.2.804.2.1.1.1.1.3.1.1.2.0")), random));
        AsymmetricCipherKeyPair keyPair1 = ecKeyPairGenerator.generateKeyPair();
        DSTU4145KeyPairGenerator keyPairGenerator1 = new DSTU4145KeyPairGenerator();
        keyPairGenerator1.init(new ECKeyGenerationParameters(DSTU4145NamedCurves.getByOID(new ASN1ObjectIdentifier("1.2.804.2.1.1.1.1.3.1.1.2.0")), random));
        AsymmetricCipherKeyPair keyPair2 = keyPairGenerator1.generateKeyPair();
        //DSTU4145NamedCurves
        KeyPairGenerator keyPairGenerator2 = KeyPairGenerator.getInstance("DSTU4145","BC");
        keyPairGenerator2.initialize(ecGenParameterSpec, random);

        KeyPair keyPair3 = keyPairGenerator2.generateKeyPair();
        BCDSTU4145PrivateKey privateKey = (BCDSTU4145PrivateKey) keyPair3.getPrivate();
        System.out.println();
  */  }

}
