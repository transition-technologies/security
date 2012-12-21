package security.role;

import java.util.List;

public interface RoleHolder {

    List<? extends Role> getRoles();

}
