package org.auspicacious.akman.lib.impl;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.auspicacious.akman.lib.interfaces.CertificateValidator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

@Slf4j
public class DefaultCertificateValidator implements CertificateValidator {
  private final CertPath certPath;

  /**
   * Initialize the validator and construct a certificate path that
   * will be used for all validation requests.
   *
   * @param caFilesOrDirs A collection of Paths that are either files
   *     containing certificate authorities, or directories containing
   *     only certificate authority files.
   * @param trustRootSelector A selector that will uniquely identify
   *     the trust root.
   * @param intermediateSelector A selector that will uniquely
   *     identify the intermediate certificate.
   */
  public DefaultCertificateValidator(final Collection<Path> caFilesOrDirs,
                                     final CertSelector trustRootSelector,
                                     final CertSelector intermediateSelector) {
    final Collection<X509CertificateHolder> allCertificates = new ArrayList<>();
    for (final Path caFileOrDir : caFilesOrDirs) {
      allCertificates.addAll(loadCAs(caFileOrDir));
    }
    this.certPath = createCertPath(allCertificates, trustRootSelector, intermediateSelector);
  }

  /**
   * Initialize the validator and construct a certificate path that
   * will be used for all validation requests.
   *
   * @param caFileOrDir A Path that is either a file containing
   *     multiple certificate authorities, or a directory containing
   *     only certificate authority files.
   * @param trustRootSelector A selector that will uniquely identify
   *     the trust root.
   * @param intermediateSelector A selector that will uniquely
   *     identify the intermediate certificate.
   */
  public DefaultCertificateValidator(final Path caFileOrDir,
                                     final CertSelector trustRootSelector,
                                     final CertSelector intermediateSelector) {
    this.certPath = createCertPath(loadCAs(caFileOrDir), trustRootSelector, intermediateSelector);
  }

  @SuppressWarnings("PMD.NullAssignment")
  private DefaultCertificateValidator() {
    this.certPath = null;
  }
  
  @Override
  public boolean validate(final X509CertificateHolder cert) {
    return certPath.equals(new Object());
  }

  private static CertPath createCertPath(final Collection<X509CertificateHolder> trustedCertHolders,
                                         final CertSelector trustRootSelector,
                                         final CertSelector intermediateSelector) {
    final Collection<Certificate> certs = convertToJCACertificates(trustedCertHolders);
    final CertStore certStore;
    try {
      certStore = CertStore.getInstance("Collection",
                                        new CollectionCertStoreParameters(certs),
                                        BouncyCastleProvider.PROVIDER_NAME);
    } catch (final GeneralSecurityException e) {
      throw new AkmanRuntimeException(
          "Problem creating a CertStore. Most likely a problem in the JDK configuration.", e);
    }

    final X509Certificate trustRoot = findCertificate(certStore, trustRootSelector);

    final Set<TrustAnchor> trustAnchor = new HashSet<>();
    trustAnchor.add(new TrustAnchor(trustRoot, null));
    final PKIXBuilderParameters params;
    try {
      params = new PKIXBuilderParameters(trustAnchor, intermediateSelector);
    } catch (InvalidAlgorithmParameterException e) {
      throw new AkmanRuntimeException(
          "The trustAnchor HashSet was not populated. This should not happen.",
          e);
    }
    params.setRevocationEnabled(false);
    params.addCertStore(certStore);

    final CertPath certPath;
    try {
      certPath = CertPathBuilder.getInstance("PKIX",
                                             BouncyCastleProvider.PROVIDER_NAME)
        .build(params).getCertPath();
    } catch (CertPathBuilderException e) {
      throw new AkmanRuntimeException("Could not generate a certificate validation path.", e);
    } catch (InvalidAlgorithmParameterException
             | NoSuchAlgorithmException
             | NoSuchProviderException e) {
      throw new AkmanRuntimeException(
          "Could not find some component needed to build the certpath.", e);
    }

    log.debug("certificate path: {}", certPath);
    return certPath;
  }

  private static Collection<Certificate> convertToJCACertificates(
      final Collection<X509CertificateHolder> trustedCertHolders) {
    final JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME);
    final Collection<Certificate> certs = new ArrayList<>();
    try {
      for (final X509CertificateHolder certHolder : trustedCertHolders) {
        final X509Certificate cert = certConverter.getCertificate(certHolder);
        certs.add(cert);
      }
    } catch (final CertificateException e) {
      throw new AkmanRuntimeException(
          "Issue while converting from BouncyCastle to JCE X509Certificate object.", e);
    }
    return certs;
  }

  @SuppressWarnings("unchecked")
  private static X509Certificate findCertificate(final CertStore certStore,
                                                 final CertSelector selector) {
    final Collection<X509Certificate> certs;
    try {
      certs = (Collection<X509Certificate>) certStore.getCertificates(selector);
    } catch (CertStoreException e) {
      throw new AkmanRuntimeException(
          "An exception occurred while locating one of the certificates.",
          e);
    }
    if (certs.size() > 1) {
      throw new IllegalArgumentException("The selector does not uniquely identify a certificate.");
    } else if (certs.isEmpty()) {
      throw new IllegalArgumentException("The selector did not identify any certificates.");
    }
    return certs.iterator().next();
  }
    
  @SuppressFBWarnings("RCN_REDUNDANT_NULLCHECK_WOULD_HAVE_BEEN_A_NPE")
  private static Collection<X509CertificateHolder> loadCAs(final Path caFileOrDir) {
    if (Files.isRegularFile(caFileOrDir)) {
      return loadCAFile(caFileOrDir);
    } else if (Files.isDirectory(caFileOrDir)) {
      final BiPredicate<Path, BasicFileAttributes> predicate = (path, attr) -> attr.isRegularFile();
      try (Stream<Path> caFileStream = Files.find(caFileOrDir,
                                                  Integer.MAX_VALUE,
                                                  predicate,
                                                  (FileVisitOption) null)) {
        caFileStream.forEach(file -> loadCAFile(file));
      } catch (IOException e) {
        throw new AkmanRuntimeException("Problem accessing starting file for CA file search.", e);
      }
    } else {
      throw new IllegalArgumentException(caFileOrDir.toString()
                                         + " is not a regular file or directory and cannot be read."
                                         );
    }
    return null;
  }

  private static Collection<X509CertificateHolder> loadCAFile(final Path caFile) {
    if (!Files.isRegularFile(caFile)) {
      throw new IllegalArgumentException(caFile.toString()
                                         + " is not a regular file and cannot be read.");
    }
    final List<X509CertificateHolder> certHolderList = new ArrayList<>();
    try (
         Reader fileReader = Files.newBufferedReader(caFile);
         PemReader pemReader = new PemReader(fileReader)
         ) {
      while (true) {
        final PemObject pemObject = pemReader.readPemObject();
        if (pemObject == null) {
          break;
        }
        certHolderList.add(new X509CertificateHolder(pemObject.getContent()));
      }
    } catch (IOException e) {
      throw new AkmanRuntimeException("An error occurred while parsing the CA file.", e);
    }
    return certHolderList;
  }
}
