package model;

import security.role.Role;

/**
 *
 * @author piechutm
 */
public enum UserRole implements Role {
    USER, ADMIN;

    public String getRoleName() {
        return name();
    }


    
}
