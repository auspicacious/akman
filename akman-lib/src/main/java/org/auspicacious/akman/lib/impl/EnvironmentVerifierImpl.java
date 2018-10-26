package org.auspicacious.akman.lib.impl;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EnvironmentVerifierImpl {
    public boolean verify() {
        // https://wiki.apache.org/commons/Logging/StaticLog
        // TODO this shouldn't be called a verifier if it has side effects

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        StringBuilder s = new StringBuilder();
        for (Provider provider : Security.getProviders()) {
            s.append(provider.getName());
            s.append(": ");
            s.append(provider.getInfo());
            s.append(System.lineSeparator());
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
                    s.append(serviceName);
                    s.append(": ");
                    s.append(name);
                    s.append(" (alias for ");
                    s.append(provider.get("Alg.Alias." + entry));
                    s.append(")");
                    s.append(System.lineSeparator());
                } else {
                    s.append(serviceName);
                    s.append(": ");
                    s.append(name);
                    s.append(System.lineSeparator());
                }
            }
        }
        log.info(s.toString());

        try {
            return Cipher.getMaxAllowedKeyLength("AES") >= 256;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
