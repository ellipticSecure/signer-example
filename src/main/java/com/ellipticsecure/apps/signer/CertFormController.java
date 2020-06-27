/*
 * Copyright (c) 2020 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */
package com.ellipticsecure.apps.signer;

import javafx.fxml.FXML;
import javafx.scene.control.Spinner;
import javafx.scene.control.TextField;

/**
 * JavaFX view controller for the certificate dialog.
 *
 * @author Kobus Grobler
 */
public class CertFormController {

    @FXML
    public TextField cnTf;
    @FXML
    public TextField localityTf;
    @FXML
    public TextField countryTf;

    @FXML
    public Spinner<Integer> validitySpinner;

}
