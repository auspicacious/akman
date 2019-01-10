package org.auspicacious.akman.server;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509CertSelector;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.auspicacious.akman.lib.impl.DefaultCertificateValidator;
import org.auspicacious.akman.lib.interfaces.CertificateValidator;
import org.auspicacious.akman.server.servlets.ValidateServlet;

/**
 * This class inspired by:
 * https://github.com/seanjreilly/httpServletExample
 */
@WebListener
public class AkmanServletContextListener implements ServletContextListener {
  @Override
  public void contextInitialized(final ServletContextEvent sce) {
    final X509CertSelector trustRootSelector = new X509CertSelector();
    final X509CertSelector intermediateSelector = new X509CertSelector();
    try {
      trustRootSelector.addSubjectAlternativeName(1, "akmanrootca1@akman.auspicacious.org");
      intermediateSelector.addSubjectAlternativeName(1, "akmansubca1@akman.auspicacious.org");
    } catch (IOException e) {
      throw new AkmanRuntimeException("There was a problem creating the certificate selectors.", e);
    }

    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    final CertificateValidator validator = new DefaultCertificateValidator(
        caDir, trustRootSelector, intermediateSelector);

    final ServletContext context = sce.getServletContext();
    context.addServlet("validate", new ValidateServlet(validator)).addMapping("/validate");
  }

  @Override
  public void contextDestroyed(final ServletContextEvent sce) {
    // no implementation necessary
  }
}
