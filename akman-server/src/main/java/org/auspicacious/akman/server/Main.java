package org.auspicacious.akman.server;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.catalina.WebResourceRoot;
import org.apache.catalina.WebResourceSet;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.webresources.DirResourceSet;
import org.apache.catalina.webresources.EmptyResourceSet;
import org.apache.catalina.webresources.StandardRoot;

@SuppressFBWarnings("PATH_TRAVERSAL_IN")
@SuppressWarnings({"checkstyle:multiplestringliterals",
      "checkstyle:magicnumber",
      "PMD.ShortClassName",
      "PMD.SignatureDeclareThrowsException",
      "PMD.SystemPrintln",})
public final class Main {
  private Main() {
    // do nothing
  }

  @SuppressWarnings({"PMD.AvoidThrowingRawExceptionTypes",})
  private static File getRootFolder() {
    try {
      File root;
      final String runningJarPath = Main.class.getProtectionDomain()
          .getCodeSource().getLocation().toURI().getPath()
          .replaceAll("\\\\", "/");
      final int lastIndexOf = runningJarPath.lastIndexOf("/target/");
      if (lastIndexOf < 0) {
        root = new File("");
      } else {
        root = new File(runningJarPath.substring(0, lastIndexOf));
      }
      System.out.println("application resolved root folder: " + root.getAbsolutePath());
      return root;
    } catch (URISyntaxException ex) {
      throw new RuntimeException(ex);
    }
  }

  /**
   * Run the application.
   *
   * @throws Exception this is the entry point to the application.
   */
  public static void main(final String[] args) throws Exception {
    System.setProperty("org.apache.catalina.startup.EXIT_ON_INIT_FAILURE", "true");

    final Tomcat tomcat = new Tomcat();
    tomcat.getConnector();
    final Path tempPath = Files.createTempDirectory("tomcat-base-dir");
    // TODO delete on exit
    tomcat.setBaseDir(tempPath.toString());
    tomcat.setPort(8080);
    // TODO better doc base

    final File webContentFolder = Files.createTempDirectory("default-doc-base").toFile();
    final StandardContext ctx =
        (StandardContext) tomcat.addWebapp("", webContentFolder.getAbsolutePath());
    // Set execution independent of current thread context classloader
    // (compatibility with exec:java mojo)
    ctx.setParentClassLoader(Thread.currentThread().getContextClassLoader());

    System.out.println("configuring app with basedir: " + webContentFolder.getAbsolutePath());

    // Declare an alternative location for your "WEB-INF/classes" dir
    // Servlet 3.0 annotation will work
    final File root = getRootFolder();
    final File additionWebInfClassesFolder = new File(root.getAbsolutePath(), "target/classes");
    final WebResourceRoot resources = new StandardRoot(ctx);

    final WebResourceSet resourceSet;
    if (additionWebInfClassesFolder.exists()) {
      resourceSet = new DirResourceSet(resources,
                                       "/WEB-INF/classes",
                                       additionWebInfClassesFolder.getAbsolutePath(),
                                       "/");
      // resourceSet = new DirResourceSet(resources,
      // "/WEB-INF/classes",
      // additionWebInfClassesFolder.getAbsolutePath(), "/");
      System.out.println("loading WEB-INF resources from as '"
                         + additionWebInfClassesFolder.getAbsolutePath() + "'");
    } else {
      resourceSet = new EmptyResourceSet(resources);
    }
    resources.addPreResources(resourceSet);
    ctx.setResources(resources);

    tomcat.start();
    tomcat.getServer().await();
  }
}
