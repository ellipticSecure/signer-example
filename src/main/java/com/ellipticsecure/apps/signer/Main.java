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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * Signer example app Main class
 * @author Kobus Grobler
 */
public class Main extends Application {

    private static String version ="DEV";

    private static Main instance;

    public static Main getInstance() { return instance;}

    @Override
    public void start(Stage primaryStage) throws Exception {
        instance = this;
        Parent root = FXMLLoader.load(getClass().getResource("main.fxml"));
        primaryStage.getIcons().add(new Image(getClass().getResourceAsStream("icon_512x512.png")));
        primaryStage.setTitle("ellipticSecure PDF Signer "+version);
        primaryStage.setScene(new Scene(root));
        primaryStage.setResizable(false);
        primaryStage.show();
    }

    public static void main(String[] args) throws IOException{
        setVersion();
        launch(args);
    }

    private static void setVersion() throws IOException {
        Class<Main> clazz = Main.class;
        String className = clazz.getSimpleName() + ".class";
        String classPath = clazz.getResource(className).toString();
        if (classPath.startsWith("jar")) {
            String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) +
                    "/META-INF/MANIFEST.MF";
            try (InputStream in = new URL(manifestPath).openStream()) {
                Manifest manifest = new Manifest(in);
                Attributes attr = manifest.getMainAttributes();
                version = attr.getValue("Implementation-Version");
            }
        }
    }
}
