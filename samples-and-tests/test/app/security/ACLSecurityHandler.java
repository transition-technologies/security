package security;

import exception.SecurityException;
import security.handler.AccessHandler;
import security.handler.SecurityHandler;
import security.role.RoleHolder;


public class ACLSecurityHandler implements SecurityHandler {

    DynamicResourcesHandler dynamicResourcesHandler = new DynamicResourcesHandler();
    
    public void beforeRoleCheck() {
    }

    public RoleHolder getRoleHolder() {
        return null;
    }

    public void onAccessFailure(String paramString) {
        throw new SecurityException(paramString);
    }

    public AccessHandler getAccessHandler() {
        return dynamicResourcesHandler;
    }
}
