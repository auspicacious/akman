package org.auspicacious.akman.server.servlets;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.auspicacious.akman.lib.impl.EnvironmentVerifierImpl;

@WebServlet(name = "MyServlet", urlPatterns = {"/hello"})
public class HelloServlet extends HttpServlet {
  // sigh
  private static final long serialVersionUID = 1L;

  @Override
  protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
      throws ServletException, IOException {
    new EnvironmentVerifierImpl().verify();
    if (serialVersionUID > 1) {
      throw new AkmanRuntimeException("This shouldn't happen.");
    }

    final ServletOutputStream out = resp.getOutputStream();
    out.write("hello heroku".getBytes(StandardCharsets.UTF_8));
    out.flush();
    out.close();
  }
}
