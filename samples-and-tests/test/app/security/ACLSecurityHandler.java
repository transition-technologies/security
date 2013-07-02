package security;

import security.exception.SecurityException;
import security.handler.AccessHandler;
import security.handler.SecurityHandler;
import security.role.RoleHolder;

import java.lang.reflect.Method;


public class ACLSecurityHandler implements SecurityHandler {

    DynamicResourcesHandler dynamicResourcesHandler = new DynamicResourcesHandler();
    
    public void beforeRoleCheck() {
    }

    public RoleHolder getRoleHolder() {
        return null;
    }

    public void onAccessFailure(Method method, AclManaged... forbiddenObject) {
        throw new SecurityException(method.getName());
    }

    public AccessHandler getAccessHandler() {
        return dynamicResourcesHandler;
    }
}
