/*
 * Copyright (c) 2020 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */

package com.ellipticsecure.apps.signer;

import com.ellipticsecure.ehsm.CKTokenInfo;
import com.ellipticsecure.ehsm.EHSMConfig;
import com.ellipticsecure.ehsm.EHSMLibrary;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.CallbackHandler;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.*;

import static com.ellipticsecure.ehsm.CKFlags.CKF_SERIAL_SESSION;
import static com.ellipticsecure.ehsm.CKFlags.CKF_TOKEN_INITIALIZED;
import static com.ellipticsecure.ehsm.CKReturnValues.CKR_OK;

/**
 * A Helper class to manage the PKCS11 provider for a MIRkey or eHSM hardware security module.
 *
 * @author Kobus Grobler
 */
public class PKCS11Helper {

    private static final Logger logger = LoggerFactory.getLogger(PKCS11Helper.class);

    private static PKCS11Helper instance;

    private long slot = 0;

    private boolean sessionTimeoutsEnabled = false;

    private AuthProvider provider;

    private EHSMLibrary ehsmlib;

    private CallbackHandler callbackHandler;

    private PKCS11Helper() {}

    /**
     * Returns an instance of the PKCS11Helper class.
     * @return the instance
     */
    public static PKCS11Helper getInstance() {
        if (instance == null) {
            instance = new PKCS11Helper();
        }
        return instance;
    }

    /**
     * Set the callback handler that will prompt the user for a PIN when required.
     * @param handler the callback handler
     */
    public void setCallbackHandler(CallbackHandler handler) {
        callbackHandler = handler;
        if (provider != null) {
            provider.setCallbackHandler(handler);
        }
    }

    /**
     * Return an initialized and configured PKCS11 provider.
     * @return the provider
     */
    public AuthProvider getProvider() {
        initProvider();
        return provider;
    }

    /**
     * Gets a PKCS11 backed keystore instance.
     *
     * @return the keystore
     * @throws IOException if an io related error occurs
     * @throws GeneralSecurityException if a security exception occurs
     */
    public KeyStore getKeyStore() throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance("PKCS11", getProvider());
        provider.login(null, null);
        ks.load(null, null);
        return ks;
    }

    /**
     * Cleans up the provider instance and logs out from the device.
     * @throws GeneralSecurityException if a security error occurs during cleanup.
     */
    public void cleanupProvider() throws GeneralSecurityException {
        if (provider != null) {
            provider.logout();
            Security.removeProvider(provider.getName());
            provider.clear();
            // The SunPKCS11 provider does not close sessions (or recover from CKR_SESSION_CNT error)
            // - manually close sessions here.
            ehsmlib.C_CloseAllSessions(new NativeLong(slot));
            provider = null;
            ehsmlib = null;
        }
    }

    /**
     * This method should be called on a frequency that is higher than the session timeout value if the device
     * has been configured to automatically close sessions after a specified timeout. This method will
     * keep the sessions alive.
     */
    public void keepalive() {
        if (ehsmlib != null && sessionTimeoutsEnabled) {
            NativeLongByReference pSession = new NativeLongByReference();

            // This is just to keep sessions alive if a session timeout has been configured.
            // The SunPKCS11 provider does not recover from CRK_SESSION_INVALID errors.
            long r = ehsmlib.C_OpenSession(new NativeLong(slot), new NativeLong(CKF_SERIAL_SESSION), Pointer.NULL, Pointer.NULL, pSession);
            if (r == CKR_OK) {
                ehsmlib.C_CloseSession(pSession.getValue());
            }
        }
    }

    private void initProvider() {
        if (provider == null) {
            String lib = System.getenv("EHSM_LIBRARY");
            if (lib == null) {
                lib = getDefaultLibrary();
            }

            if (ehsmlib == null) {
                ehsmlib = EHSMLibrary.getInstance(lib);
            }
            long r = ehsmlib.C_Initialize(Pointer.NULL);
            try {
                NativeLong[] pSlotList = new NativeLong[10];
                NativeLongByReference pCount = new NativeLongByReference(new NativeLong(pSlotList.length));
                EHSMLibrary.throwIfNotOK(ehsmlib.C_GetSlotList((byte) 1, pSlotList, pCount));
                if (pCount.getValue().longValue() == 0) {
                    throw new ProviderException("No devices found.");
                }

                slot = pSlotList[0].longValue();

                CKTokenInfo info = new CKTokenInfo();
                EHSMLibrary.throwIfNotOK(ehsmlib.C_GetTokenInfo(pSlotList[0],info));
                if ((info.flags.longValue() & CKF_TOKEN_INITIALIZED) == 0) {
                    throw new ProviderException("The device has not been initialized yet.");
                }

                EHSMConfig config = new EHSMConfig();
                EHSMLibrary.throwIfNotOK(ehsmlib.u32GetTokenConfig(pSlotList[0],config));
                if (config.u8SessionTimeout > 0) {
                    sessionTimeoutsEnabled = true;
                }
            } finally {
                if (r == CKR_OK) { // if we initialized it, then also call finalize.
                    ehsmlib.C_Finalize(Pointer.NULL);
                }
            }

            NativeLibrary nativeLibrary = NativeLibrary.getInstance(EHSMLibrary.getDefaultLibraryName());
            lib = nativeLibrary.getFile().getAbsolutePath(); // SunPKCS11 requires absolute .dll path on Windows.

            logger.debug("Initializing PKCS11 provider with {}", lib);
            StringWriter sw = new StringWriter();
            PrintWriter printWriter = new PrintWriter(sw);
            printWriter.println("--name = MIRkey");
            printWriter.println("slot = "+ slot);
            printWriter.println("library = " + lib);
            printWriter.flush();
            try {
                try {
                    // jdk > 8
                    Method configure = Provider.class.getDeclaredMethod("configure", String.class);
                    provider = (AuthProvider) Security.getProvider("SunPKCS11");
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
            if (callbackHandler != null) {
                provider.setCallbackHandler(callbackHandler);
            }
            Security.addProvider(provider);
        }
    }

    private static String getDefaultLibrary() {
        return EHSMLibrary.getDefaultLibraryName();
    }
}
