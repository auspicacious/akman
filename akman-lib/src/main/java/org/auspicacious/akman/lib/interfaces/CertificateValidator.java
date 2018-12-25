package org.auspicacious.akman.lib.interfaces;

import java.security.cert.X509Certificate;

/**
 * Interface for classes that certify a certificate as valid. The
 * certification rules will depend on the implementation.
 */
public interface CertificateValidator {
  /**
   * Indicate whether the given certificate is considered valid.
   *
   * @return true, if the certificate is valid according to the rules
   *     of the validator in use. Otherwise false.
   */
  boolean validate(X509Certificate cert);
}
