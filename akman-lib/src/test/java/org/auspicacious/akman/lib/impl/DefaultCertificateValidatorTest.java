package org.auspicacious.akman.lib.impl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

public class DefaultCertificateValidatorTest {
  @BeforeSuite
  public void setupEnvironment() {
    new EnvironmentVerifierImpl().verify();
  }
    
  @Test
  public void testCollectionConstructorFilesOnly() throws Exception {
    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    final List<Path> caFiles = new ArrayList<>();
    caFiles.add(caDir.resolve("akmanrootca1.crt"));
    caFiles.add(caDir.resolve("akmansubca1.crt"));

    final X509CertSelector trustRootSelector = new X509CertSelector();
    trustRootSelector.addSubjectAlternativeName(1, "akmanrootca1@akman.auspicacious.org");
    final X509CertSelector intermediateSelector = new X509CertSelector();
    intermediateSelector.addSubjectAlternativeName(1, "akmansubca1@akman.auspicacious.org");

    new DefaultCertificateValidator(caFiles, trustRootSelector, intermediateSelector);
  }

  @Test
  public void testSingleFileConstructor() throws Exception {
    final Path caFile = Path.of("src", "test", "resources", "certs",
                                "validclientcert-singlefileca", "ca", "ca.crt");

    final X509CertSelector trustRootSelector = new X509CertSelector();
    trustRootSelector.addSubjectAlternativeName(1, "akmanrootca1@akman.auspicacious.org");
    final X509CertSelector intermediateSelector = new X509CertSelector();
    intermediateSelector.addSubjectAlternativeName(1, "akmansubca1@akman.auspicacious.org");

    new DefaultCertificateValidator(caFile, trustRootSelector, intermediateSelector);
  }
}
