package org.auspicacious.akman.lib.impl;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EnvironmentVerifierImpl {
    public boolean verify() {
        // https://wiki.apache.org/commons/Logging/StaticLog
        // TODO this shouldn't be called a verifier if it has side effects

        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            return Cipher.getMaxAllowedKeyLength("AES") > 128;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
