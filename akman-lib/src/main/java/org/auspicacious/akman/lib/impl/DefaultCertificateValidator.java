package org.auspicacious.akman.lib.impl;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.cert.CertPath;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.function.BiPredicate;
import java.util.stream.Stream;
import org.auspicacious.akman.lib.interfaces.CertificateValidator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class DefaultCertificateValidator implements CertificateValidator {
    private final CertPath certPath = null;

    public DefaultCertificateValidator(final Collection<Path> caFilesOrDirs) {
    }

    public DefaultCertificateValidator(final Path caFileOrDir) {
    }

    @Override
    public boolean validate(final X509CertificateHolder cert) {
        return false;
    }

    // TODO maybe these should be in a static utility class if they
    // are useful elsewhere
    private static Collection<X509CertificateHolder> loadCAs(final Path caFileOrDir) throws IOException {
        if (Files.isRegularFile(caFileOrDir)) {
            return loadCAFile(caFileOrDir);
        } else if (Files.isDirectory(caFileOrDir)) {
            final BiPredicate<Path, BasicFileAttributes> predicate = (path, attr) -> attr.isRegularFile();
            try (Stream<Path> caFileStream = Files.find(caFileOrDir, Integer.MAX_VALUE, predicate, (FileVisitOption) null)) {
                caFileStream.forEach(file -> loadCAFile(file));
            }
        } else {
            throw new IllegalArgumentException("Path " + caFileOrDir.toString() + "is not a regular file or directory and cannot be read.");
        }
        return null;
    }

    private static Collection<X509CertificateHolder> loadCAFile(final Path caFile) {
        if (!Files.isRegularFile(caFile)) {
            throw new IllegalArgumentException("Path " + caFile.toString() + "is not a regular file and cannot be read.");
        }
        try {
            return loadCAReader(Files.newBufferedReader(caFile));
        } catch (IOException e) {
            throw new RuntimeException();
        }
    }

    private static Collection<X509CertificateHolder> loadCAReader(final Reader reader) throws IOException {
        final List<X509CertificateHolder> certHolderList = new ArrayList<>();
        final PemReader pemReader = new PemReader(reader);
        while (true) {
            final PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                break;
            }
            certHolderList.add(new X509CertificateHolder(pemObject.getContent()));
        }
        return certHolderList;
    }

    private DefaultCertificateValidator() {
    }
}
