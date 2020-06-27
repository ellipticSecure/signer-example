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
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.Certificate;

/**
 * Sign a PDF using a MIRkey or eHSM hardware security module.
 *
 * @author Kobus Grobler
 */
public class PDFSigner {
    private static final Logger logger = LoggerFactory.getLogger(PDFSigner.class);

    private static AuthProvider provider;

    /**
     * Sign the provided PDF file.
     *
     * @param alias the key alias
     * @param ksPIN the MIRkey/eHSM PIN
     * @param in    the input file name
     * @param out   the output stream for the signed file
     * @throws IOException              if the signing fails
     * @throws GeneralSecurityException if a security related exception occurs.
     */
    public void sign(String alias, char[] ksPIN, String in, OutputStream out) throws IOException, GeneralSecurityException {
        initProviders();
        logger.info("Signing {} with {}", in, alias);

        PdfSigner pdfSigner = new PdfSigner(new PdfReader(in), out, new StampingProperties());

        KeyStore ks = getKeyStore(ksPIN);
        try {
            PrivateKeySignature pks = getPrivateKeySignature(ks, ksPIN, alias);
            Certificate[] chain = getCertificateChain(ks, alias);
            pdfSigner.signDetached(new BouncyCastleDigest(), pks, chain, null, null, null,
                    0, PdfSigner.CryptoStandard.CMS);

        } finally {
            provider.logout();
        }
    }

    public KeyStore getKeyStore(char[] password) throws IOException, GeneralSecurityException {
        initProviders();
        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, password);
        return ks;
    }

    protected PrivateKeySignature getPrivateKeySignature(KeyStore ks, char[] password, String alias) throws GeneralSecurityException {
        PrivateKey pk = (PrivateKey) ks.getKey(alias, password);
        if (pk == null) {
            return null;
        }
        return new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider.getName());
    }

    protected Certificate[] getCertificateChain(KeyStore ks, String alias) throws GeneralSecurityException {
        return ks.getCertificateChain(alias);
    }

    private static String getDefaultLibrary() {
        String os = System.getProperty("os.name");
        if (os.toLowerCase().contains("mac")) {
            return "/usr/local/lib/libehsm.dylib";
        } else if (os.toLowerCase().contains("windows")) {
            return "ehsm.dll";
        } else {
            return "/usr/local/lib/libehsm.so";
        }
    }

    private static void initProviders() {
        if (provider == null) {
            StringWriter sw = new StringWriter();
            PrintWriter printWriter = new PrintWriter(sw);
            printWriter.println("--name = MIRkey");
            printWriter.println("slot = 0");
            String lib = System.getenv("EHSM_LIBRARY");
            if (lib == null) {
                lib = getDefaultLibrary();
            }
            logger.info("Initializing PKCS11 provider with {}", lib);
            printWriter.println("library = " + lib);
            printWriter.flush();
            try {
                try {
                    // jdk > 8
                    Method configure = Provider.class.getDeclaredMethod("configure", String.class);
                    provider = (AuthProvider)Security.getProvider("SunPKCS11");
                    provider = (AuthProvider)configure.invoke(provider,sw.toString());
                } catch (NoSuchMethodException nme) {
                    // jdk 8
                    Constructor construct = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(String.class);
                    provider = (AuthProvider)construct.newInstance(sw.toString());
                }
            } catch (InvocationTargetException | InstantiationException ite) {
                logger.warn("Failed to init PKCS11 Provider.", ite);
                provider = null;
                throw new ProviderException(ite.getCause());
            } catch (ReflectiveOperationException nse) {
                logger.warn("Failed to create PKCS11 Provider.", nse);
                provider = null;
                throw new ProviderException(nse.getCause());
            }
            Security.addProvider(provider);
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
