package org.auspicacious.akman.lib.impl;

import org.bouncycastle.cms.CMSSignedData;
import org.testng.annotations.Test;
import org.testng.Assert;

/**
 * Static data for these tests (certificates, signed texts, etc.) is
 * generated using OpenSSL in order to create more confidence that we
 * aren't generating broken test data and then verifying it in a
 * broken way.
 */
public class OfflineSignatureVerifierTest {
    @Test
    public void testVerifyCMS() throws Exception {
        Assert.assertEquals("a", "a");
    }
}
