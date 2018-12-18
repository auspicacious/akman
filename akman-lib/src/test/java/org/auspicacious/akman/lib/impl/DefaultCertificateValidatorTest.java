package org.auspicacious.akman.lib.impl;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

public class DefaultCertificateValidatorTest {
  private static final X509CertSelector trustRootSelector = new X509CertSelector();
  private static final X509CertSelector intermediateSelector = new X509CertSelector();
  static {
    try {
      trustRootSelector.addSubjectAlternativeName(1, "akmanrootca1@akman.auspicacious.org");
      intermediateSelector.addSubjectAlternativeName(1, "akmansubca1@akman.auspicacious.org");
    } catch (IOException e) {
      throw new AkmanRuntimeException("There was a problem creating the certificate selectors.", e);
    }
  }

  @BeforeSuite
  public void setupEnvironment() {
    new EnvironmentVerifierImpl().verify();
  }

  @Test
  public void testCollectionConstructorDirectoryOnly() throws Exception {
    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    new DefaultCertificateValidator(caDir,
                                    (X509CertSelector) trustRootSelector.clone(),
                                    (X509CertSelector) intermediateSelector.clone());
  }

  @Test
  public void testCollectionConstructorFilesOnly() throws Exception {
    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    final List<Path> caFiles = new ArrayList<>();
    caFiles.add(caDir.resolve("akmanrootca1.crt"));
    caFiles.add(caDir.resolve("akmansubca1.crt"));

    new DefaultCertificateValidator(caFiles,
                                    (X509CertSelector) trustRootSelector.clone(),
                                    (X509CertSelector) intermediateSelector.clone());
  }

  @Test
  public void testSingleFileConstructor() throws Exception {
    final Path caFile = Path.of("src", "test", "resources", "certs",
                                "validclientcert-singlefileca", "ca", "ca.crt");
    new DefaultCertificateValidator(caFile,
                                    (X509CertSelector) trustRootSelector.clone(),
                                    (X509CertSelector) intermediateSelector.clone());
  }

  @Test(expectedExceptions = { NullPointerException.class, })
  public void testNullFileConstructor() throws Exception {
    final Path caFile = null;
    new DefaultCertificateValidator(caFile,
                                    (X509CertSelector) trustRootSelector.clone(),
                                    (X509CertSelector) intermediateSelector.clone());
  }

  @Test(expectedExceptions = { NullPointerException.class, })
  public void testNullListConstructor() throws Exception {
    final List<Path> caFiles = null;
    new DefaultCertificateValidator(caFiles,
                                    (X509CertSelector) trustRootSelector.clone(),
                                    (X509CertSelector) intermediateSelector.clone());
  }

  // TODO test null selectors as well as selectors that match nothing
  // or multiple certificates. Test a list with null entries.

  @Test
  public void testValidate() throws IOException {
    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    new DefaultCertificateValidator(caDir,
                                    (X509CertSelector) trustRootSelector.clone(),
                                    (X509CertSelector) intermediateSelector.clone());
  }
}
