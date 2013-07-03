package security.exception;


import security.AclManaged;

import java.lang.reflect.Method;

public class SecurityException extends RuntimeException {

    private static final long serialVersionUID = -3609286207240970458L;
    private final AclManaged[] forbiddenObjects;
    private final Method forbiddenMethod;

    public SecurityException() {
        this(null);
    }

    public SecurityException(String message) {
        this(message, null);
    }

    public SecurityException(String message, Throwable cause) {
        this(message, cause, null);
    }

    public SecurityException(String message, Throwable cause, Method forbiddenMethod, AclManaged... forbiddenObjects){
        super(message, cause);
        this.forbiddenMethod = forbiddenMethod;
        this.forbiddenObjects = forbiddenObjects;
    }

    public SecurityException(String message, Method forbiddenMethod, AclManaged[] forbiddenObjects) {
        this(message, null, forbiddenMethod, forbiddenObjects);
    }

    public Method getForbiddenMethod() {
        return forbiddenMethod;
    }

    public AclManaged[] getForbiddenObjects() {
        return forbiddenObjects;
    }
}
