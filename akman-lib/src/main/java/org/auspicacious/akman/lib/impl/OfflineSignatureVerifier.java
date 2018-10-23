package org.auspicacious.akman.lib.impl;

import java.security.Security;
import java.util.Collection;
import org.auspicacious.akman.lib.impl.SignatureVerifierException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

/**
 * The "offline" refers to the lack of an OCSP server being necessary
 * for its behavior. OCSP stapling or an up-to-date CRL is
 * required. (TODO, better name for this)
 */
public class OfflineSignatureVerifier {
    // @Override
    // public boolean verifyCertificate(X509CertificateHolder cert) {
    //     ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder()
    //         .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pubKey);
    //     cert.isSignatureValid(contentVerifierProvider);
    // }

    public boolean verifyCMS(CMSSignedData s) throws Exception {
        // TODO where to check OCSP stapling and other revocation
        // mechanisms, and how to communicate that usefully
        // vs. expired certs?

        // TODO does this verify the signature on the message envelope
        // or something else? I don't see 
        Store<X509CertificateHolder> signerCerts = s.getCertificates();
        SignerInformationStore signerInfoStore = s.getSignerInfos();
        for (SignerInformation signer : signerInfoStore) {
            X509CertificateHolder cert = (X509CertificateHolder) signerCerts.getMatches(signer.getSID()).iterator().next();
            Boolean verification = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(cert));
            System.out.println("verification result: " + verification.toString());
        }
        Collection<X509CertificateHolder> certColl = signerCerts.getMatches(null);
        if (certColl.size() != s.getCertificates().getMatches(null).size()) {
            // TODO this is from the BC test suite, what does it do?
            // It seems to be comparing the same thing repeatedly.
            return false;
        }

        return true;
    }
}
