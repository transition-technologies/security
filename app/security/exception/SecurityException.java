package security.exception;


public class SecurityException extends RuntimeException {

    private static final long serialVersionUID = -3609286207240970458L;

    public SecurityException() {
        super();
    }

    public SecurityException(String message) {
        super(message);
    }

    public SecurityException(String message, Throwable cause) {
        super(message, cause);
    }

}
