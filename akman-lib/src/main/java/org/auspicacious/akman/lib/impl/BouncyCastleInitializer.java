package org.auspicacious.akman.lib.impl;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import lombok.extern.slf4j.Slf4j;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Slf4j
public final class BouncyCastleInitializer {
  private static final AtomicInteger INVOCATION_COUNT = new AtomicInteger(0);
  private static final int MIN_AES_STRENGTH = 256;

  private BouncyCastleInitializer() {
  }

  /**
   * Only run this method once per JVM. It will validate that your JVM
   * can support the encryption operations necessary for this
   * application and add the Bouncy Castle encryption provider.
   */
  @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
  public static synchronized void initialize() {
    try {
      if (Cipher.getMaxAllowedKeyLength("AES") < MIN_AES_STRENGTH) {
        throw new AkmanRuntimeException(
          "Cannot use this JVM as it does not have sufficient encryption strength available. "
          + "Try searching for instructions on how to apply an unlimited encryption strength "
          + "policy.");
      }
    } catch (NoSuchAlgorithmException e) {
      throw new AkmanRuntimeException(
        "Tried to check the strength of the AES encryption "
        + " algorithm, but it does not seem to be available in this JVM!", e);
    }

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    if (INVOCATION_COUNT.getAndIncrement() == 0
        && System.getProperty("akman.logCryptoDebugInfo") != null) {
      logDebugInfo();
    }
  }

  @SuppressWarnings("checkstyle:multiplestringliterals")
  private static void logDebugInfo() {
    final StringBuilder s = new StringBuilder();
    for (final Provider provider : Security.getProviders()) {
      s.append(provider.getName());
      s.append(": ");
      s.append(provider.getInfo());
      s.append(System.lineSeparator());
      for (final Object entryObj : provider.keySet()) {
        String entry = (String) entryObj;
        boolean isAlias = false;
        if (entry.startsWith("Alg.Alias")) {
          isAlias = true;
          entry = entry.substring("Alg.Alias".length() + 1);
        }
        final String serviceName = entry.substring(0, entry.indexOf('.'));
        final String name = entry.substring(serviceName.length() + 1);
        if (isAlias) {
          s.append(serviceName);
          s.append(": ");
          s.append(name);
          s.append(" (alias for ");
          s.append(provider.get("Alg.Alias." + entry));
          s.append(')');
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
  }
}
