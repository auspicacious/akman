package org.auspicacious.akman.server.servlets;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.auspicacious.akman.lib.interfaces.CertificateValidator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// None of these servlets are actually serializable
@SuppressFBWarnings("SE_BAD_FIELD")
@WebServlet(name = "validate", urlPatterns = {"/validate"})
public class ValidateServlet extends HttpServlet {
  private static final ThreadLocal<CertificateFactory> CERT_FACTORY =
      ThreadLocal.withInitial(() -> {
        try {
          return CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        } catch (final NoSuchProviderException | CertificateException e) {
          throw new AkmanRuntimeException("Problem creating a new CertificateFactory instance.", e);
        }
      });

  // sigh
  private static final long serialVersionUID = 1L;

  private final CertificateValidator validator;

  public ValidateServlet(final CertificateValidator validator) {
    super();
    this.validator = validator;
  }

  @Override
  @SuppressFBWarnings("RCN_REDUNDANT_NULLCHECK_WOULD_HAVE_BEEN_A_NPE")
  protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
      throws ServletException, IOException {
    final X509Certificate cert;
    try (ServletInputStream in = request.getInputStream()) {
      cert = (X509Certificate) CERT_FACTORY.get().generateCertificate(in);
    } catch (CertificateException | IOException e) {
      throw new ServletException("An error occurred while parsing the CA file.", e);
    }

    validator.validate(cert);

    try (ServletOutputStream out = response.getOutputStream()) {
      out.write("true".getBytes(StandardCharsets.UTF_8));
    }
  }
}
