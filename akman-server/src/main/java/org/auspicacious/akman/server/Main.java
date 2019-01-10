package org.auspicacious.akman.server;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.apache.catalina.startup.Tomcat;
import org.auspicacious.akman.lib.impl.BouncyCastleInitializer;

@SuppressWarnings({"checkstyle:magicnumber",
      "PMD.ShortClassName",
      "PMD.SignatureDeclareThrowsException", })
public final class Main {
  // TODO get rid of all of this, switch to gRPC?

  private Main() {
    // do nothing
  }

  /**
   * Run the application.
   *
   * @throws Exception this is the entry point to the application.
   */
  public static void main(final String[] args) throws Exception {
    BouncyCastleInitializer.initialize();
    System.setProperty("org.apache.catalina.startup.EXIT_ON_INIT_FAILURE", "true");

    final Path tomcatDir = Files.createTempDirectory(
        "tomcat-",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));

    final Tomcat tomcat = new Tomcat();
    tomcat.getConnector();
    tomcat.setPort(8080);
    tomcat.addContext("/api", tomcatDir.toAbsolutePath().toString())
      .addApplicationListener("org.auspicacious.akman.server.AkmanServletContextListener");
    tomcat.start();

    try {
      tomcat.getServer().await();
    } finally {
      tomcat.stop();
    }
  }
}
