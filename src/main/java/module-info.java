/**
 * Signing example app module dependencies
 * @author Kobus Grobler
 */
module signer.example {
    requires jdk.crypto.cryptoki;
    requires javafx.fxml;
    requires javafx.controls;

    requires org.slf4j.jul;
    requires org.slf4j;

    // bc
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;

    // itext
    requires sign;
    requires kernel;

    requires ehsm.java;
    requires com.sun.jna;

    exports com.ellipticsecure.apps.signer;
    opens com.ellipticsecure.apps.signer to javafx.fxml;
}
