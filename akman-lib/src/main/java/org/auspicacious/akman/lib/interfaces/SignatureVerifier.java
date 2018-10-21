package org.auspicacious.akman.lib.interfaces;

import org.auspicacious.akman.lib.impl.SignatureVerifierException;

public interface SignatureVerifier {
    public boolean verify() throws SignatureVerifierException;
}
