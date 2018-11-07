package org.auspicacious.akman.lib.impl;

import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;
import java.security.cert.CertSelector;
import java.security.cert.X509CertSelector;
import javax.security.auth.x500.X500Principal;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.ArrayList;
import java.math.BigInteger;

public class DefaultCertificateValidatorTest {
    @BeforeSuite
    public void setupEnvironment() {
        new EnvironmentVerifierImpl().verify();
    }
    
    @Test
    public void testCollectionConstructor() {
        final List<Path> caFiles = new ArrayList<>();
        caFiles.add(Paths.get("/home/at/projects/code/openvpn2018/ca/certs/ca.cert.pem"));
        caFiles.add(Paths.get("/home/at/projects/code/openvpn2018/ca/intermediate/certs/intermediate.cert.pem"));

        final X509CertSelector trustRootSelector = new X509CertSelector();
        trustRootSelector.setSerialNumber(new BigInteger("82981b9f84207540", 16));
        final X509CertSelector intermediateSelector = new X509CertSelector();
        intermediateSelector.setSerialNumber(new BigInteger("1000", 16));
        new DefaultCertificateValidator(caFiles, trustRootSelector, intermediateSelector);
    }
}
