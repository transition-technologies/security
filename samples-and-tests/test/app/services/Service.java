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
        System.out.println("Access for admin only");
    }
    
    @RoleRequired({"ADMIN", "USER"})
    public void accessForAdminAndUser() {
        System.out.println("Access for admin and user");
    }

    @RoleRequired({"USER"})
    public void accessForUserOnly() {
        System.out.println("Access for user only");
    }
}

