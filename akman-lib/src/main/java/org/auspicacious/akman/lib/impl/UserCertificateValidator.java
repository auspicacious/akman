package org.auspicacious.akman.lib.impl;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;
import java.io.Reader;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.io.IOException;

/**
 * Validate that a provided end-user certificate was signed by a CA we
 * trust and has only acceptable parameters.
 */
public class UserCertificateValidator {
    /**
     * This method needs to be moved, of course. Take a cert in PEM
     * format and convert it to BER, then create a useful Java
     * structure.
     */
    public List<X509CertificateHolder> parsePEMCertificate(final Reader reader) throws IOException {
        final List<X509CertificateHolder> certHolderList = new ArrayList<>();
        final PemReader pemReader = new PemReader(reader);
        while (true) {
            final PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                break;
            }
            System.out.println(new String(pemObject.getContent(), StandardCharsets.UTF_8));
        }
        return certHolderList;
    }

    public boolean validate(X509CertificateHolder userCert) {
        return false;
    }
}
