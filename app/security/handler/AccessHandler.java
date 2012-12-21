package security.handler;

import java.util.Map;

import security.role.RoleHolder;

import security.annotation.Access;



public interface AccessHandler {
    
    /**
     * Check access for objects based on object access map, where key is context object and value specifies access checks for
     * current user.
     * 
     * <ul>
     * <li>If {@link AccessResult#NOT_SPECIFIED} is returned and
     * {@link controllers.deadbolt.RestrictedResource#staticFallback()} is false, access is denied.</li>
     * <li>If {@link AccessResult#NOT_SPECIFIED} is returned and
     * {@link controllers.deadbolt.RestrictedResource#staticFallback()} is true, any further RoleRequired or Restrictions
     * annotations are processed. Note that if no RoleRequired or Restrictions annotations are present, access will be allowed.</li>
     * </ul>
     * @param roleHolder 
     * 
     * @param objectAccessMap the object access map
     * @return the access result
     */
    AccessResult checkAccess(RoleHolder roleHolder, Map<Object, Access> objectAccessMap);

}
