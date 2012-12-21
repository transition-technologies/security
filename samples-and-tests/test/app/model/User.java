package model;

import java.util.LinkedList;
import java.util.List;

import security.role.RoleHolder;

import security.AclManaged;


public class User implements RoleHolder, AclManaged {

    List<UserRole> roles = new LinkedList<UserRole>();
    
    public List<UserRole> getRoles() {
        return roles;
    }
}
