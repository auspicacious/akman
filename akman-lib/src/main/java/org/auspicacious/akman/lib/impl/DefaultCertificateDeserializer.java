package org.auspicacious.akman.lib.impl;

import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import org.auspicacious.akman.lib.interfaces.CertificateDeserializer;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class DefaultCertificateDeserializer implements CertificateDeserializer {
  @Override
  public List<X509CertificateHolder> readPEMCertificates(final Reader reader)
      throws IOException {
    final List<X509CertificateHolder> certHolderList = new ArrayList<>();
    try (PemReader pemReader = new PemReader(reader)) {
      while (true) {
        final PemObject pemObject = pemReader.readPemObject();
        if (pemObject == null) {
          break;
        }
        certHolderList.add(new X509CertificateHolder(pemObject.getContent()));
      }
    }
    return certHolderList;
  }
}
