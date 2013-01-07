package services;

import security.annotation.RoleRequired;
import security.annotation.AnyRole;

public class Service {

    @AnyRole
    public void securedMethod() {
    }

    public void nonSecuredMethod() {
    }
    
    @RoleRequired({"ADMIN"})
    public void accessForAdminOnly() {
    }
    
    @RoleRequired({"ADMIN", "USER"})
    public void accessForAdminOrUser() {
    }

    @RoleRequired({"USER"})
    public void accessForUserOnly() {
    }
}

