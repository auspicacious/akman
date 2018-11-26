package org.auspicacious.akman.lib.exceptions;

/**
 * Many classes throw checked exceptions for unusual conditions that
 * can't really be handled intelligently in code and will need to be
 * handled by an engineer. This class is used to wrap those
 * exceptions.
 */
public class AkmanRuntimeException extends RuntimeException {
  // Do not attempt to serialize.
  private static final long serialVersionUID = 1L;

  public AkmanRuntimeException(final String message) {
    super(message);
  }

  public AkmanRuntimeException(final String message, final Throwable t) {
    super(message, t);
  }

  /**
   * Always provide at least a message.
   */
  private AkmanRuntimeException() {
    super();
  }
}
