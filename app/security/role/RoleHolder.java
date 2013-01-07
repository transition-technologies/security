package security.role;

import java.util.List;

/**
 * The User holding roles.
 * 
 * @author Maciej Kujawski <M.Kujawski@tt.com.pl>
 */
public interface RoleHolder {

    List<? extends Role> getRoles();

}
