package org.auspicacious.akman.lib.interfaces;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Interface for classes that certify a certificate as valid. The
 * certification rules will depend on the implementation.
 */
public interface CertificateValidator {
    boolean validate(X509CertificateHolder cert);
}
