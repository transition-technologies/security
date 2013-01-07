package security.handler;

import java.util.Map;

import security.annotation.Access;
import security.annotation.Access.AccessType;
import security.role.RoleHolder;

/**
 * The AccessHandler manages access to objects for given role holder.
 * 
 * @author Maciej Kujawski <M.Kujawski@tt.com.pl>
 */
public interface AccessHandler {

    /**
     * Check access for objects based on object access map, where key is context object and value specifies access checks for
     * current user.
     * 
     * @param roleHolder
     * 
     * @param objectAccessMap the object access map
     * @return the access result
     */
    AccessResult checkAccess(RoleHolder roleHolder, Map<Object, Access> objectAccessMap);

    /**
     * Checks roleHolder has access for context object.
     * 
     * @param roleHolder the role holder
     * @param contextObject the context object
     * @param accessTypes the access types
     * @return the access result
     */
    AccessResult checkAccess(RoleHolder roleHolder, Object contextObject, AccessType[] accessTypes);

}
