package org.auspicacious.akman.lib.impl;

public class SignatureVerifierException extends Exception {
    public SignatureVerifierException(String message) {
        super(message);
    }

    public SignatureVerifierException(String message, Throwable cause) {
        super(message, cause);
    }
}
