/*
 * Copyright (c) 2020 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */

package com.ellipticsecure.apps.signer;

import javax.security.auth.callback.CallbackHandler;
import java.io.IOException;
import java.security.AuthProvider;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * This an interface for ProviderHelper classes.
 *
 * @author Kobus Grobler
 */
public interface ProviderHelper {

    /**
     * Set the callback handler that will prompt the user for a PIN when required.
     * @param handler the callback handler
     */
    void setCallbackHandler(CallbackHandler handler);

    /**
     * Return an initialized and configured PKCS11 provider.
     * @return the provider
     */
    AuthProvider getProvider();

    /**
     * Gets a PKCS11 backed keystore instance.
     *
     * @return the keystore
     * @throws IOException if an io related error occurs
     * @throws GeneralSecurityException if a security exception occurs
     */
    KeyStore getKeyStore() throws IOException, GeneralSecurityException;

    /**
     * Cleans up the provider instance and logs out from the device.
     * @throws GeneralSecurityException if a security error occurs during cleanup.
     */
    void cleanupProvider() throws GeneralSecurityException;

    /**
     * This method should be called on a frequency that is higher than the session timeout value if the device
     * has been configured to automatically close sessions after a specified timeout. This method will
     * keep the sessions alive.
     */
    void keepalive();
}
