package org.auspicacious.akman.lib.impl;

import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertSelector;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.auspicacious.akman.lib.interfaces.CertificateDeserializer;
import org.bouncycastle.cert.X509CertificateHolder;
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
    final DefaultCertificateValidator validator = instantiateStandardValidator(caDir);
  }

  @Test
  public void testCollectionConstructorFilesOnly() throws Exception {
    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    final List<Path> caFiles = new ArrayList<>();
    caFiles.add(caDir.resolve("akmanrootca1.crt"));
    caFiles.add(caDir.resolve("akmansubca1.crt"));
    final DefaultCertificateValidator validator = instantiateStandardValidator(caFiles);
  }

  @Test
  public void testSingleFileConstructor() throws Exception {
    final Path caFile = Path.of("src", "test", "resources", "certs",
                                "validclientcert-singlefileca", "ca", "ca.crt");
    final DefaultCertificateValidator validator = instantiateStandardValidator(caFile);
  }

  @Test(expectedExceptions = { NullPointerException.class, })
  public void testNullFileConstructor() throws Exception {
    final Path caFile = null;
    final DefaultCertificateValidator validator = instantiateStandardValidator(caFile);
  }

  @Test(expectedExceptions = { NullPointerException.class, })
  public void testNullListConstructor() throws Exception {
    final List<Path> caFiles = null;
    final DefaultCertificateValidator validator = instantiateStandardValidator(caFiles);
  }

  // TODO test null selectors as well as selectors that match nothing
  // or multiple certificates. Test a list with null entries.

  @Test
  public void testValidate() throws Exception {
    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    final DefaultCertificateValidator validator = instantiateStandardValidator(caDir);
    final Path clientCertPath = Path.of("src", "test", "resources", "certs",
                                        "validclientcert-multifileca", "akmanclient1.crt");
    final X509CertificateHolder clientCert;
    try (Reader fileReader = Files.newBufferedReader(clientCertPath)) {
      clientCert = new DefaultCertificateDeserializer().readPEMCertificates(fileReader).get(0);
    }
    // validator.validate(clientCert);
  }

  private DefaultCertificateValidator instantiateStandardValidator(List<Path> caFiles) {
    final CertificateDeserializer certDeserializer = new DefaultCertificateDeserializer();
    return new DefaultCertificateValidator(caFiles,
                                           (X509CertSelector) trustRootSelector.clone(),
                                           (X509CertSelector) intermediateSelector.clone(),
                                           certDeserializer);
  }

  private DefaultCertificateValidator instantiateStandardValidator(Path caFile) {
    final CertificateDeserializer certDeserializer = new DefaultCertificateDeserializer();
    return new DefaultCertificateValidator(caFile,
                                           (X509CertSelector) trustRootSelector.clone(),
                                           (X509CertSelector) intermediateSelector.clone(),
                                           certDeserializer);
  }
}
