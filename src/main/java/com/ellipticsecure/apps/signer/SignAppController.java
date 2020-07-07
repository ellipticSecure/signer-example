/*
 * Copyright (c) 2020 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */
package com.ellipticsecure.apps.signer;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.HostServices;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
import javafx.util.Duration;
import org.bouncycastle.operator.OperatorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * JavaFX view controller for the signer app.
 *
 * @author Kobus Grobler
 */
public class SignAppController implements CallbackHandler {
    private static final Logger logger = LoggerFactory.getLogger(SignAppController.class);

    private final PDFSigner signer = new PDFSigner();

    private File initialDir;

    private PKCS11Helper pkcs11Helper;

    private boolean loggedIn = false;

    @FXML
    private DialogPane certDialogPane;
    @FXML
    private CertFormController certDialogPaneController;

    @FXML
    private Button loginBt;

    @FXML
    private Button generateCertBt;

    @FXML
    private Label dropTarget;

    @FXML
    private ChoiceBox<String> keysCb;

    @FXML
    private TextArea certDescription;

    private final Map<String, X509Certificate> aliasMap = new HashMap<>();

    @FXML
    protected void dragOver(DragEvent evt) {
        if (evt.getGestureSource() != dropTarget
                && evt.getDragboard().hasFiles()) {
            evt.acceptTransferModes(TransferMode.COPY);
        }
        evt.consume();
    }

    @FXML
    protected void dropFileAction(DragEvent evt) {
        Dragboard db = evt.getDragboard();
        boolean success = false;
        if (db.hasFiles() && loggedIn && !keysCb.getSelectionModel().isEmpty()) {
            File fileIn = db.getFiles().get(0);
            if (fileIn.getName().toLowerCase().endsWith(".pdf")) {
                success = true;
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Save Signed File");
                if (initialDir == null) {
                    fileChooser.setInitialDirectory(
                            new File(System.getProperty("user.home"))
                    );
                } else {
                    fileChooser.setInitialDirectory(initialDir);
                }
                String newFileName = fileIn.getName().replaceAll(".pdf", " signed.pdf");
                fileChooser.setInitialFileName(newFileName);
                File file = fileChooser.showSaveDialog(dropTarget.getScene().getWindow());
                if (file != null) {
                    initialDir = file.getParentFile();
                    try {
                        try (FileOutputStream fileOutputStream =
                                     new FileOutputStream(file.getAbsolutePath())) {
                            signer.sign(keysCb.getSelectionModel().getSelectedItem(), fileIn.getAbsolutePath(), fileOutputStream);
                        }

                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "File successfully signed.", ButtonType.OK);
                        alert.showAndWait();

                    } catch (Exception exception) {
                        logger.warn("Failed to sign PDF", exception);
                        Alert alert = new Alert(Alert.AlertType.ERROR,
                                "Failed to sign PDF. (" + getErrorMessage(exception) + ")", ButtonType.OK);
                        alert.showAndWait();
                    }
                }
            }
        }
        evt.setDropCompleted(success);
        evt.consume();
    }

    @FXML
    protected void generateCertBtAction() {
        Dialog<ButtonType> dialog = new Dialog<>();
        dialog.setDialogPane(certDialogPane);
        dialog.showAndWait().ifPresent(response -> {
            if (response == ButtonType.OK) {
                try {
                    generateTestCert(certDialogPaneController.validitySpinner.getValue(),
                            certDialogPaneController.cnTf.getText(),
                            certDialogPaneController.localityTf.getText(),
                            certDialogPaneController.countryTf.getText());

                } catch (Exception e) {
                    logger.error("Failed to generate cert", e);
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "Failed to generate certificate. (" + getErrorMessage(e) + ")", ButtonType.OK);
                    alert.showAndWait();
                }
            }
        });
    }

    @FXML
    protected void loginBtAction() {
        if (!loggedIn) {
            try {
                populatePrivateKeyAliases();

                keysCb.setDisable(false);
                if (!keysCb.getItems().isEmpty()) {
                    keysCb.getSelectionModel().select(0);
                } else {
                    Alert alert = new Alert(Alert.AlertType.WARNING,
                            "There are no certificates on the device that can be used for signing - create or import a certificate using the ellipticSecure Device Manager.",
                            ButtonType.OK);
                    alert.showAndWait();
                }
                dropTarget.setDisable(false);
                loggedIn = true;
                generateCertBt.setDisable(false);
                loginBt.setText("Log out");
            } catch (Exception e) {
                logger.warn("Failed to open keystore", e);
                String message = getErrorMessage(e);
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "Failed to log in to device. (" + message + ")", ButtonType.OK);
                alert.showAndWait();
            }
        } else {
            loginBt.setText("Enter device PIN");
            try {
                pkcs11Helper.cleanupProvider();
            } catch (Exception e) {
                logger.warn("An error occurred during cleanup.", e);
            }
            loggedIn = false;
            keysCb.getItems().clear();
            aliasMap.clear();
            keysCb.setDisable(true);
            dropTarget.setDisable(true);
            generateCertBt.setDisable(true);
            certDescription.setText("");
        }
    }

    private void generateTestCert(Integer validity, String cn, String locality, String country) throws OperatorException, GeneralSecurityException, IOException {
        KeyStore ks = pkcs11Helper.getKeyStore();
        if (ks.containsAlias(cn)) {
            Alert alert = new Alert(Alert.AlertType.ERROR,
                    "The device already contains a certificate with name " + cn, ButtonType.OK);
            alert.showAndWait();
            return;
        }

        // Generate a volatile session keypair on the MIRkey device
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", ks.getProvider());
        ECGenParameterSpec kpgparams = new ECGenParameterSpec("secp256r1");
        g.initialize(kpgparams);
        KeyPair keyPair = g.generateKeyPair();

        // Generate a certificate for the key
        X509Certificate cert = CertUtils.generateTestCertFromKeyPair(
                keyPair,
                validity,
                "SHA256withECDSA",
                "CN=" + cn + ", L=" + locality + ", C=" + country, null);

        // Persist the keypair and associated certificate to non-volatile storage on the MIRkey device
        ks.setKeyEntry(cn, keyPair.getPrivate(), null, new X509Certificate[]{cert});
        aliasMap.put(cn,(X509Certificate)ks.getCertificate(cn));
        keysCb.getItems().add(cn);
        keysCb.getSelectionModel().select(cn);
    }

    private void populatePrivateKeyAliases() throws GeneralSecurityException, IOException {
        keysCb.getItems().clear();
        aliasMap.clear();
        KeyStore ks = pkcs11Helper.getKeyStore();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            logger.debug("Keystore alias: {}", alias);
            if (ks.isKeyEntry(alias)) {
                Key key = ks.getKey(alias, null);
                if (key instanceof PrivateKey) {
                    X509Certificate cert = (X509Certificate)ks.getCertificate(alias);
                    logger.info("Cert: {}",cert);
                    keysCb.getItems().add(alias);
                    aliasMap.put(alias, cert);
                }
            }
        }
    }

    private static String getErrorMessage(Throwable e) {
        String message = e.getMessage();
        if (e.getCause() != null) {
            // get the root cause
            Throwable c = e.getCause();
            while (c.getCause() != null) {
                c = c.getCause();
            }
            if (message != null) {
                message += ":" + c.getMessage();
            } else {
                message = c.getMessage();
            }
        }
        return message;
    }

    private char[] getPIN() {
        Dialog<String> dialog = new Dialog<>();
        dialog.setTitle("Device log-in");
        dialog.setHeaderText("The device security user PIN is required to perform signing.");
        dialog.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);

        PasswordField pwd = new PasswordField();
        HBox content = new HBox();
        content.setAlignment(Pos.CENTER_LEFT);
        content.setSpacing(10);
        content.getChildren().addAll(new Label("Please enter the MIRkey SU PIN:"), pwd);
        dialog.getDialogPane().setContent(content);
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == ButtonType.OK) {
                return pwd.getText();
            }
            return null;
        });
        pwd.setFocusTraversable(true);
        dialog.setOnShown(event -> pwd.requestFocus());
        Optional<String> result = dialog.showAndWait();
        return result.map(String::toCharArray).orElse(null);
    }

    public void iconClickAction() {
        HostServices hostServices = Main.getInstance().getHostServices();
        hostServices.showDocument("https://ellipticsecure.com");
    }

    private void displaySelectedCert(String alias) {
        X509Certificate cert = aliasMap.get(alias);
        certDescription.setText(cert.toString());
    }

    @FXML
    public void initialize() {
        pkcs11Helper = PKCS11Helper.getInstance();
        pkcs11Helper.setCallbackHandler(this);

        Timeline timer = new Timeline(new KeyFrame(Duration.seconds(30),
                event -> pkcs11Helper.keepalive()));
        timer.setCycleCount(Timeline.INDEFINITE);
        timer.play();

        keysCb.getSelectionModel().selectedItemProperty().addListener((observableValue, old, newVal)
                -> displaySelectedCert(newVal));
    }

    @Override
    public void handle(Callback[] callbacks) {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) callback;
                pc.setPassword(getPIN());
            }
        }
    }
}
