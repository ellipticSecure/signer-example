/*
 * Copyright (c) 2020 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */
package com.ellipticsecure.apps.signer;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

/**
 * Signer example app Main class
 * @author Kobus Grobler
 */
public class Main extends Application {

    private static Main instance;

    public static Main getInstance() { return instance;}

    @Override
    public void start(Stage primaryStage) throws Exception {
        instance = this;
        Parent root = FXMLLoader.load(getClass().getResource("main.fxml"));
        primaryStage.getIcons().add(new Image(getClass().getResourceAsStream("icon_512x512.png")));
        primaryStage.setTitle("ellipticSecure PDF Signer v0.2");
        primaryStage.setScene(new Scene(root));
        primaryStage.setResizable(false);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
