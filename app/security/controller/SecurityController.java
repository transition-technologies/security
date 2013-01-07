package security.controller;

import exception.SecurityException;

import play.mvc.Catch;

import play.mvc.Controller;

/**
 * Catches all exceptions {@link SecurityException} and send forbidden response with localized message of exception
 */
public class SecurityController extends Controller {
    
    @Catch(value = SecurityException.class)
    public static void catchSecurityException(SecurityException securityException) {
        forbidden(securityException.getLocalizedMessage());
    }

}
