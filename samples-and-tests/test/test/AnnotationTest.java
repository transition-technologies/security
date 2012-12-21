import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import exception.SecurityException;
import model.User;
import model.UserRole;
import play.mvc.Http.Request;
import play.test.UnitTest;
import security.Security;
import services.ACLService;
import services.RestrictedService;
import services.Service;

public class AnnotationTest extends UnitTest {

    private Service service;
    
    private RestrictedService restrictedService;
    
    private ACLService aclService;

    @Before
    public void setUp() {
        service = new Service();
        restrictedService = new RestrictedService();
        aclService = new ACLService();
        Request.current().args.remove(Security.CACHE_PER_REQUEST);
    }
    
    @After
    public void cleanUp() {
        Request.current().args.remove(Security.CACHE_PER_REQUEST);
    }

    @Test
    public void testGuestHasAccessToSecuredMethod() {
        service.nonSecuredMethod();
    }

    @Test(expected = SecurityException.class)
    public void testGuestHasnotAccessToSecuredMethod() {
        service.securedMethod();
    }
    
    @Test
    public void testUserHasAccessToSecuredMethod() {
        User user = mockGetRoleHolder(UserRole.USER);
        Request.current().args.put(Security.CACHE_PER_REQUEST, user);
        
        service.securedMethod();
    }

    @Test(expected=SecurityException.class)
    public void testUserNotInRoleFromRestrictRoleHasnotAccessToSecuredMethod() {
        User user = mockGetRoleHolder(UserRole.USER);
        Request.current().args.put(Security.CACHE_PER_REQUEST, user);

        service.accessForAdminOnly();
    }
    
    @Test(expected=SecurityException.class)
    public void testUserHasAllRolesFromRestrictRoleToAccessSecuredMethod() throws java.lang.SecurityException, NoSuchMethodException {
        User user = mockGetRoleHolder(UserRole.ADMIN);
        Request.current().args.put(Security.CACHE_PER_REQUEST, user);
        
        service.accessForAdminAndUser();
    }
    
    @Test
    public void testGuestHasAccessToUnrestricteMethod() {
        restrictedService.doSimpleChange();
    }
    
    @Test(expected = SecurityException.class)
    public void testUserCannotAccessClassForAdminOnly() throws java.lang.SecurityException, NoSuchMethodException {
        User user = mockGetRoleHolder(UserRole.USER);
        Request.current().args.put(Security.CACHE_PER_REQUEST, user);

        restrictedService.changeEverything();
    }
    
    @Test(expected = SecurityException.class)
    public void testUserHasNoAccessToObjectsManagedByAdmin() throws java.lang.SecurityException, NoSuchMethodException {
        User user = mockGetRoleHolder(UserRole.USER);
        Request.current().args.put(Security.CACHE_PER_REQUEST, user);

        aclService.save(new User());
    }
    
    

    private User mockGetRoleHolder(UserRole... roles) {
        User user = new User();
        for (UserRole role : roles) {
            user.getRoles().add(role);
        }

        return user;
    }
}
