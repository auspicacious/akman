package org.auspicacious.akman.lib.impl;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;
import java.io.Reader;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.io.BufferedReader;
import java.nio.file.Files;
import org.testng.annotations.Test;
import org.testng.Assert;
import java.nio.file.Paths;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class UserCertificateValidatorTest {
    @Test
    public void testParsePEMCertificate() throws Exception {
        final UserCertificateValidator validator = new UserCertificateValidator();
        final List<X509CertificateHolder> certList;
        try (Reader fileReader = Files.newBufferedReader(Paths.get("/home/at/projects/code/openvpn2018/ca/intermediate/certs/client.cert.pem"))) {
            certList = validator.parsePEMCertificate(fileReader);
        }
        for (X509CertificateHolder cert : certList) {
            log.debug(cert.getSubject().toString());
        }
    }
}
