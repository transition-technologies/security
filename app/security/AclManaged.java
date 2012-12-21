package security;

import security.annotation.Access;
import security.annotation.Access.AccessType;

/**
 * Used to mark class as ACL Managed. Current user is checked against access rights of specified {@link AccessType} to
 * AclManaged object passed to method as parameter annotated with {@link Access} before method execution.
 * 
 * @author Maciej Kujawski <M.Kujawski@tt.com.pl>
 * 
 */
public interface AclManaged {

}
