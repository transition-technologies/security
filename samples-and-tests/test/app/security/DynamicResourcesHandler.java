package security;

import java.util.List;
import java.util.Map;

import security.annotation.Access;
import security.annotation.Access.AccessType;
import security.handler.AccessHandler;
import security.handler.AccessResult;
import security.role.Role;
import security.role.RoleHolder;



/**
 * Check access to given resource. Access for UPDATE, DELETE, ALL is only for ADMIN role.
 * User in USER role has only access for READ
 */
public class DynamicResourcesHandler implements AccessHandler {

    public AccessResult checkAccess(RoleHolder roleHolder, Object contextObject, AccessType[] accessTypes) {
        AccessResult result = AccessResult.DENIED;

        if (roleHolder != null && contextObject instanceof AclManaged) {
            result = aclSecurityCheck(roleHolder, accessTypes);
        }

        return result;
    }
    
    public AccessResult checkAccess(RoleHolder roleHolder, Map<Object, Access> objectAccessMap) {
        AccessResult result = AccessResult.ALLOWED;

        for (Object object : objectAccessMap.keySet()) {
            Access access = objectAccessMap.get(object);

            AccessType[] accessTypes = access.value();

            if (!access.type().equals(AclManaged.class) || object instanceof AclManaged) {
                result = aclSecurityCheck(roleHolder, accessTypes);
                if (result == AccessResult.DENIED) {
                    break;
                }
            }
        }

        return result;
    }
    
    private AccessResult aclSecurityCheck(RoleHolder roleHolder, AccessType[] accesses) {
        AccessResult result = AccessResult.DENIED;
        
        boolean isAdmin = isAdmin(roleHolder);
        boolean isAccessForUser = accesses.length == 1 && accesses[0] == AccessType.READ;
        
        if (isAdmin || isAccessForUser) {
            result = AccessResult.ALLOWED;
        }
        return result;
    }
    
    private boolean isAdmin(RoleHolder roleHolder) {
        boolean isAdmin = false;
        List<? extends Role> roles = roleHolder.getRoles();
        
        for (Role role : roles) {
            if ("ADMIN".equals(role.getRoleName())) {
                isAdmin = true;
                break;
            }
        }
        
        return isAdmin;
    }

}
