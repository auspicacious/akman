package org.auspicacious.akman.lib.impl;

public class SignatureVerifierException extends Exception {
    /** sigh */
    private static final long serialVersionUID = 1L;

    public SignatureVerifierException(String message) {
        super(message);
    }

    public SignatureVerifierException(String message, Throwable cause) {
        super(message, cause);
    }
}
