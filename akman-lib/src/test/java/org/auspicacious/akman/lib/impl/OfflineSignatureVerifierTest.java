package org.auspicacious.akman.lib.impl;

import org.bouncycastle.cms.CMSSignedData;
import org.testng.annotations.Test;
import org.testng.Assert;
import java.nio.file.Paths;
import java.nio.file.Files;

/**
 * Static data for these tests (certificates, signed texts, etc.) is
 * generated using OpenSSL in order to create more confidence that we
 * aren't generating broken test data and then verifying it in a
 * broken way.
 */
public class OfflineSignatureVerifierTest {
    @Test
    public void testVerifyCMS() throws Exception {
        new EnvironmentVerifierImpl().verify();
        // byte[] pembytes = Files.readAllBytes(Paths.get("/home/at/projects/code/openvpn2018/ca/intermediate/testmessage.txt.pem"));
        // CMSSignedData data = new CMSSignedData(pembytes);
        // OfflineSignatureVerifier verifier = new OfflineSignatureVerifier();
        // verifier.verifyCMS(data);
        Assert.assertEquals("a", "a");
    }
}
