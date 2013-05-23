package security.controller;

import play.mvc.Catch;
import play.mvc.Controller;
import security.exception.SecurityException;

/**
 * Catches all exceptions {@link SecurityException} and send forbidden response with localized message of exception
 */
public class SecurityController extends Controller {
    
    @Catch(SecurityException.class)
    public static void catchSecurityException(SecurityException securityException) {
        forbidden(securityException.getLocalizedMessage());
    }

}
