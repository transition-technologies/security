package services;

import security.annotation.RoleRequired;
import security.annotation.Unsecured;

@RoleRequired({"ADMIN"})
public class RestrictedService {

    
    public void changeEverything() {
        System.out.println("Changing everything");
    }
    
    @Unsecured
    public void doSimpleChange() {
        System.out.println("Do simple change");
    }
    
}
