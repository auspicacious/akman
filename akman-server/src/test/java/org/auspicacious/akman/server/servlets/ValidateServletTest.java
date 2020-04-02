package org.auspicacious.akman.server.servlets;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchProviderException;
import java.security.cert.CertSelector;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.auspicacious.akman.lib.exceptions.AkmanRuntimeException;
import org.auspicacious.akman.lib.impl.DefaultCertificateValidator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mockito.ArgumentMatchers;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;

public class ValidateServletTest {
  private static final X509CertSelector trustRootSelector = new X509CertSelector();
  private static final X509CertSelector intermediateSelector = new X509CertSelector();
  static {
    try {
      trustRootSelector.addSubjectAlternativeName(1, "akmanrootca1@akman.auspicacious.org");
      intermediateSelector.addSubjectAlternativeName(1, "akmansubca1@akman.auspicacious.org");
    } catch (IOException e) {
      throw new AkmanRuntimeException("There was a problem creating the certificate selectors.", e);
    }
  }

  @Test
  public void testCollectionConstructorDirectoryOnly() throws Exception {
    // TODO of course, should use mocks for a unit test. Should also
    // do a better job getting parsing logic out of the servlet.
    final Path clientCertPath = Path.of("src", "test", "resources", "certs",
                                        "validclientcert-multifileca", "akmanclient1.crt");
    final Path caDir = Path.of("src", "test", "resources", "certs",
                               "validclientcert-multifileca", "ca");
    final DefaultCertificateValidator validator = instantiateStandardValidator(caDir);
    final ValidateServlet servlet = new ValidateServlet(validator);

    // see http://blog.timmattison.com/archives/2014/12/16/mockito-and-servletinputstreams/
    final byte[] certBytes = Files.readAllBytes(clientCertPath);
    final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certBytes);
    final ServletInputStream mockServletInputStream = mock(ServletInputStream.class);
    when(mockServletInputStream.read(ArgumentMatchers.<byte[]>any(), anyInt(), anyInt())).thenAnswer(new Answer<Integer>() {
        @Override
          public Integer answer(InvocationOnMock invocationOnMock) throws Throwable {
          Object[] args = invocationOnMock.getArguments();
          byte[] output = (byte[]) args[0];
          int offset = (int) args[1];
          int length = (int) args[2];
          return byteArrayInputStream.read(output, offset, length);
        }
      });

    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getMethod()).thenReturn("POST");
    when(request.getInputStream()).thenReturn(mockServletInputStream);

    HttpServletResponse response = mock(HttpServletResponse.class);
    ServletOutputStream output = mock(ServletOutputStream.class);
    when(response.getOutputStream()).thenReturn(output);

    //execute
    servlet.service(request, response);
    //verify
    verify(output).print("true");
  }

  private DefaultCertificateValidator instantiateStandardValidator(Path caFile) {
    return new DefaultCertificateValidator(caFile,
                                           (X509CertSelector) trustRootSelector.clone(),
                                           (X509CertSelector) intermediateSelector.clone());
  }
}
