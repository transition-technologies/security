package security.handler;

import java.util.Map;

import security.AclManaged;

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
     * Checks roleHolder has access for context object.
     *
     * @param roleHolder the role holder
     * @param contextObject the context object
     * @param accessTypes the access types
     * @return the access result
     */
    AccessResult checkAccess(RoleHolder roleHolder, AclManaged contextObject, AccessType[] accessTypes);

    /**
     * Convert context object to target AclManaged to be tested for access.
     * This method is usable if ypu validate object IDs instead of objects themselves.
     * Use {@link security.annotation.Access#type()} to set target type.
     *
     * @param contextObject Object passed for validation
     * @param type          Desired type of AclManaged
     * @return Object to validate access for or null if couldn't retrieve
     */
    AclManaged toAclManaged(Object contextObject, Class<? extends AclManaged> type);
}
