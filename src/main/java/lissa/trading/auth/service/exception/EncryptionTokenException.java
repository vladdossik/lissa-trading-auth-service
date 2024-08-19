package lissa.trading.auth.service.exception;

public class EncryptionTokenException extends RuntimeException {
    public EncryptionTokenException(String message) {
        super(message);
    }

    public EncryptionTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}