package org.auspicacious.akman.lib.impl;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.io.Reader;
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
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.auspicacious.akman.lib.interfaces.CertificateDeserializer;
import org.auspicacious.akman.lib.interfaces.CertificateValidator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Slf4j
public class DefaultCertificateValidator implements CertificateValidator {
  private final CertPath certPath;
  private final Set<TrustAnchor> trustAnchors;

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
                                     final CertSelector intermediateSelector,
                                     final CertificateDeserializer certDeserializer) {
    final Collection<X509CertificateHolder> allCertificates = new ArrayList<>();
    for (final Path caFileOrDir : caFilesOrDirs) {
      allCertificates.addAll(loadCAs(caFileOrDir, certDeserializer));
    }
    this.trustAnchors = createTrustAnchors(allCertificates, trustRootSelector);
    this.certPath = createCertPath(allCertificates, this.trustAnchors, intermediateSelector);
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
                                     final CertSelector intermediateSelector,
                                     final CertificateDeserializer certDeserializer) {
    Collection<X509CertificateHolder> allCertificates = loadCAs(caFileOrDir, certDeserializer);
    this.trustAnchors = createTrustAnchors(allCertificates, trustRootSelector);
    this.certPath = createCertPath(allCertificates, this.trustAnchors, intermediateSelector);
  }

  @SuppressWarnings("PMD.NullAssignment")
  private DefaultCertificateValidator() {
    this.certPath = null;
    this.trustAnchors = null;
  }
  
  @Override
  public boolean validate(final X509CertificateHolder cert) {
    final JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter()
      .setProvider(BouncyCastleProvider.PROVIDER_NAME);
    final X509Certificate jcaCert;
    try {
      jcaCert = certConverter.getCertificate(cert);
    } catch (final CertificateException e) {
      throw new AkmanRuntimeException(
          "Issue while converting from BouncyCastle to JCE X509Certificate object.", e);
    }
    final List<Certificate> certStoreList = new ArrayList<>();
    certStoreList.add(jcaCert);
    certStoreList.addAll(this.certPath.getCertificates());
    final CertStoreParameters certStoreParams = new CollectionCertStoreParameters(certStoreList);

    final CertPath clientPath;
    try {
      final CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
      clientPath = certFactory.generateCertPath(certStoreList);
    } catch (final NoSuchProviderException|CertificateException e) {
      throw new AkmanRuntimeException("Problem generating unvalidated certificate path.", e);
    }

    final CertPathValidator cpValidator;
    final PKIXParameters pkixParams;
    final CertStore certStore;
    try {
      cpValidator = CertPathValidator.getInstance("PKIX",
                                                  BouncyCastleProvider.PROVIDER_NAME);
      pkixParams = new PKIXParameters(this.trustAnchors);
      certStore = CertStore.getInstance("Collection", certStoreParams,
                                        BouncyCastleProvider.PROVIDER_NAME);
    } catch (final InvalidAlgorithmParameterException|NoSuchAlgorithmException|NoSuchProviderException e) {
      throw new AkmanRuntimeException(
          "Problem creating JCA objects. Most likely Bouncy Castle was not initialized properly.",
          e);
    }
    pkixParams.addCertStore(certStore);
    final X509CertSelector targetSelector = new X509CertSelector();
    targetSelector.setCertificate(jcaCert);
    pkixParams.setTargetCertConstraints(targetSelector);
    pkixParams.setRevocationEnabled(false); // TODO willneed to check revocation
    final PKIXCertPathValidatorResult validatorResult;
    try {
      validatorResult =
        (PKIXCertPathValidatorResult) cpValidator.validate(clientPath, pkixParams);
    } catch (InvalidAlgorithmParameterException e) {
      throw new AkmanRuntimeException("CertPathValidator misconfiguration, should have been caught in testing", e);
    } catch (CertPathValidatorException e) {
      log.debug("Certificate path did not validate.", e);
      return false;
    }
    log.debug("validator result: {}", validatorResult);
    return true;
  }

  private static Set<TrustAnchor> createTrustAnchors(
      final Collection<X509CertificateHolder> trustedCertHolders,
      final CertSelector trustRootSelector) {
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

    return Set.of(new TrustAnchor(trustRoot, null));
  }

  private static CertPath createCertPath(final Collection<X509CertificateHolder> trustedCertHolders,
                                         final Set<TrustAnchor> trustAnchors,
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

    final PKIXBuilderParameters params;
    try {
      params = new PKIXBuilderParameters(trustAnchors, intermediateSelector);
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
    // TODO validate cert path (unclear if CertPathBuilder does this fully)
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
      throw new IllegalArgumentException("This selector does not uniquely identify a certificate:\n"
                                         + selector.toString());
    } else if (certs.isEmpty()) {
      throw new IllegalArgumentException("This selector did not identify any certificates:\n"
                                         + selector.toString());
    }
    return certs.iterator().next();
  }
    
  @SuppressFBWarnings("RCN_REDUNDANT_NULLCHECK_WOULD_HAVE_BEEN_A_NPE")
  private static Collection<X509CertificateHolder>
      loadCAs(final Path caFileOrDir, final CertificateDeserializer certDeserializer) {
    if (Files.isRegularFile(caFileOrDir)) {
      return loadCAFile(caFileOrDir, certDeserializer);
    } else if (Files.isDirectory(caFileOrDir)) {
      final Collection<X509CertificateHolder> certs = new ArrayList<X509CertificateHolder>();
      final BiPredicate<Path, BasicFileAttributes> predicate = (path, attr) -> attr.isRegularFile();
      try (Stream<Path> caFileStream = Files.find(caFileOrDir,
                                                  Integer.MAX_VALUE,
                                                  predicate)) {
        final List<Path> caFiles = caFileStream.collect(Collectors.toUnmodifiableList());
        // Using this approach instead of forEach to ensure thread
        // safety, because I'm not sure if the path stream can be
        // parallel
        for (final Path file : caFiles) {
          certs.addAll(loadCAFile(file, certDeserializer));
        }
      } catch (IOException e) {
        throw new AkmanRuntimeException("Problem accessing starting file for CA file search.", e);
      }
      return certs;
    } else {
      throw new IllegalArgumentException(caFileOrDir.toString()
                                         + " is not a regular file or directory and cannot be read."
                                         );
    }
  }

  private static Collection<X509CertificateHolder>
      loadCAFile(final Path caFile, final CertificateDeserializer certDeserializer) {
    if (!Files.isRegularFile(caFile)) {
      throw new IllegalArgumentException(caFile.toString()
                                         + " is not a regular file and cannot be read.");
    }
    try (Reader fileReader = Files.newBufferedReader(caFile)) {
      return certDeserializer.readPEMCertificates(fileReader);
    } catch (IOException e) {
      throw new AkmanRuntimeException("An error occurred while parsing the CA file.", e);
    }
  }
}
