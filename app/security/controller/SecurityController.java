package security.controller;

import exception.SecurityException;

import play.mvc.Catch;

import play.mvc.Controller;

public class SecurityController extends Controller {
    
    @Catch(value = SecurityException.class)
    public static void catchSecurityException(SecurityException securityException) {
        forbidden(securityException.getLocalizedMessage());
    }

}
