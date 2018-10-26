package org.auspicacious.akman.lib.impl;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;

public class EnvironmentVerifierImpl {
    public boolean verify() {
        // https://wiki.apache.org/commons/Logging/StaticLog
        // TODO this shouldn't be called a verifier if it has side effects

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        for (Provider provider : Security.getProviders()) {
            System.out.print(provider.getName());
            System.out.print(": ");
            System.out.print(provider.getInfo());
            System.out.println();
            for (Object entryObj : provider.keySet()) {
                String entry = (String) entryObj;
                boolean isAlias = false;
                if (entry.startsWith("Alg.Alias")) {
                    isAlias = true;
                    entry = entry.substring("Alg.Alias".length() + 1);
                }
                String serviceName = entry.substring(0, entry.indexOf('.'));
                String name = entry.substring(serviceName.length() + 1);
                if (isAlias) {
                    System.out.print(serviceName + ": " + name);
                    System.out.println(" (alias for " + provider.get("Alg.Alias." + entry) + ")");
                } else {
                    System.out.println(serviceName + ": " + name);
                }
            }
        }

        try {
            return Cipher.getMaxAllowedKeyLength("AES") >= 256;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
