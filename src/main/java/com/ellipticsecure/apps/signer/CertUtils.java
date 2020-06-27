/*
 * Copyright (c) 2020 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */
package com.ellipticsecure.apps.signer;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Utility class to help generate X509 Certificates.
 *
 * @author Kobus Grobler
 */
public class CertUtils {

    private CertUtils() {
    }

    /**
     * Generate a self-signed test certificate.
     * @param pair key pair to use
     * @param validDays validity days
     * @param algorithm siging algorithm to use (i.e. SHA256withECDSA)
     * @param dn the certificate distinguished name
     * @param provider the provider to use.
     * @return the certificate
     */
    public static X509Certificate generateTestCertFromKeyPair(KeyPair pair, int validDays, String algorithm, String dn, String provider)
            throws GeneralSecurityException, IOException, OperatorException {

        X500Name issuerName = new X500Name(dn);
        BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt()).abs();
        Calendar calendar = Calendar.getInstance();
        Date startDate = new Date();
        calendar.setTime(startDate);
        calendar.add(Calendar.DAY_OF_YEAR, validDays);
        Date endDate = calendar.getTime();

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, startDate, endDate, issuerName, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
        builder.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(pair.getPrivate());

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        if (provider != null)
            converter.setProvider(provider);
        X509Certificate cert = converter.getCertificate(builder.build(contentSigner));
        cert.checkValidity(new Date());
        cert.verify(pair.getPublic());
        return cert;
    }
}
