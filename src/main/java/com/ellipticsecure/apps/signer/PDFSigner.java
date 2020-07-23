/*
 * Copyright (c) 2020 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */

package com.ellipticsecure.apps.signer;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * Sign a PDF using a MIRkey or eHSM hardware security module.
 *
 * @author Kobus Grobler
 */
public class PDFSigner {

    private static final Logger logger = LoggerFactory.getLogger(PDFSigner.class);

    private final ProviderHelper pkcs11Helper;

    public PDFSigner() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        pkcs11Helper = EHSMProviderHelper.getInstance();
    }

    /**
     * Sign the provided PDF file.
     *
     * @param alias the key alias
     * @param in    the input file name
     * @param out   the output stream for the signed file
     * @throws IOException              if the signing fails
     * @throws GeneralSecurityException if a security related exception occurs.
     */
    public void sign(String alias, String in, OutputStream out) throws IOException, GeneralSecurityException {
        logger.info("Signing {} with {}", in, alias);
        PdfSigner pdfSigner = new PdfSigner(new PdfReader(in), out, new StampingProperties());
        KeyStore ks = pkcs11Helper.getKeyStore();
        PrivateKeySignature pks = getPrivateKeySignature(ks, alias);
        Certificate[] chain = getCertificateChain(ks, alias);
        pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null,
                0, PdfSigner.CryptoStandard.CMS);
    }

    protected PrivateKeySignature getPrivateKeySignature(KeyStore ks, String alias) throws GeneralSecurityException {
        PrivateKey pk = null;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (alias.equals(a) && ks.isKeyEntry(a)) {
                pk = (PrivateKey) ks.getKey(alias, null);
                if (pk != null)
                    break;
            }
        }
        if (pk == null) {
            logger.warn("Private key for alias {} is null.",alias);
            return null;
        }
        return new PrivateKeySignature(pk, DigestAlgorithms.SHA256, pkcs11Helper.getProvider().getName());
    }

    protected Certificate[] getCertificateChain(KeyStore ks, String alias) throws GeneralSecurityException {
        return ks.getCertificateChain(alias);
    }

}
