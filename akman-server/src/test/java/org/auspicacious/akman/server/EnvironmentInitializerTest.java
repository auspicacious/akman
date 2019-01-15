package org.auspicacious.akman.lib.impl;

import org.auspicacious.akman.lib.impl.BouncyCastleInitializer;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

/**
 * This class exists since the BouncyCastleInitializer needs to be run
 * once before the test suite starts, and this avoids hiding that
 * requirement in any particular test class.
 */
public class EnvironmentInitializerTest {
  @BeforeSuite
  public void setupEnvironment() {
    BouncyCastleInitializer.initialize();
  }
}
