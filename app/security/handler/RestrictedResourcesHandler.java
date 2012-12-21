package security.handler;

import java.util.List;
import java.util.Map;

import security.role.RoleHolder;



public interface RestrictedResourcesHandler
{
    
    /**
     * Check the access of someone, typically the current user, for the named resource.
     * 
     * <ul>
     * <li>If {@link AccessResult#NOT_SPECIFIED} is returned and
     *
     * @param roleHolder the role holder
     * @param resourceNames the names of the resource
     * @param resourceParameters additional information on the resource
     * @return {@link AccessResult#ALLOWED} if access is permitted.  {@link AccessResult#DENIED} if access is denied.
     * {@link controllers.deadbolt.RestrictedResource#staticFallback()} is false, access is denied.</li>
     * <li>If {@link AccessResult#NOT_SPECIFIED} is returned and
     * {@link controllers.deadbolt.RestrictedResource#staticFallback()} is true, any further RoleRequired or
     * Restrictions annotations are processed.  Note that if no RoleRequired or Restrictions annotations are present,
     * access will be allowed.</li>
     * </ul>
     * {@link AccessResult#NOT_SPECIFIED} if access is not specified.
     */
    AccessResult checkAccess(RoleHolder roleHolder, List<String> resourceNames,
                             Map<String, Object> resourceParameters);
}
