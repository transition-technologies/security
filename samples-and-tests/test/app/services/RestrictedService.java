package services;

import security.annotation.RoleRequired;
import security.annotation.Unsecured;

@RoleRequired({"ADMIN"})
public class RestrictedService {

    
    public void changeEverything() {
    }
    
    @Unsecured
    public void doSimpleChange() {
    }
    
}
