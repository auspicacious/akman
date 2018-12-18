package org.auspicacious.akman.lib.interfaces;

import java.io.IOException;
import java.io.Reader;
import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Interface for classes that can transform a serialized certificate
 * into a Java class.
 */
public interface CertificateDeserializer {
  /**
   * Given a PEM-encoded input reader, output all of the certificates
   * found by the reader.
   *
   * @return A list containing all of the certificates found by the
   *     reader.
   */
  List<X509CertificateHolder> readPEMCertificates(Reader reader) throws IOException;
}
