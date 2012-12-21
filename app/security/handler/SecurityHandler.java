package security.handler;

import security.role.RoleHolder;

import security.annotation.Access;


public interface SecurityHandler
{
    /**
     * Invoked immediately before controller or view restrictions are checked.  This forms the integration with any
     * authentication actions that may need to occur.
     */
    void beforeRoleCheck();

    /**
     * Gets the current {@link RoleHolder}, e.g. the current user.
     *
     * @return the current role holder
     */
    RoleHolder getRoleHolder();

    /**
     * Invoked when an access failure is detected on <i>controllerClassName</i>.
     *
     * @param controllerClassName the name of the controller access was denied to
     */
    void onAccessFailure(String controllerClassName);

    /**
     * Gets the handler used for dealing with resources restricted to specific users/groups.
     *
     * @return the handler for restricted resources.  May be null.
     */
    RestrictedResourcesHandler getRestrictedResourcesHandler();
    
    /**
     * Gets the access handler which performs access checks based on {@link Access}.
     *
     * @return the access handler
     */
    AccessHandler getAccessHandler();
}
