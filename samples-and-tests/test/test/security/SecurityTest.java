package security;

import model.User;
import model.UserRole;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import play.test.UnitTest;
import security.exception.SecurityException;
import security.handler.AccessHandler;
import security.handler.SecurityHandler;
import services.ACLService;
import services.RestrictedService;
import services.Service;

public class SecurityTest extends UnitTest {

    Security security;
    
    @Before
    public void setUpMocks() {
        SecurityHandler securityHandler = new ACLSecurityHandler();
        
        security = Security.getInstance();
        security.securityHandler = securityHandler;
    }
    
    @Test(expected=SecurityException.class)
    public void testRoleHolderPresent() throws java.lang.SecurityException, NoSuchMethodException {
        security.executeSecurityChecks(Service.class, "securedMethod", new Class<?>[] {});
    }

    @Test(expected=SecurityException.class)
    public void testUserIsNotInRoleFromRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler securityHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        security.securityHandler = securityHandler;
        
        security.executeSecurityChecks(Service.class, "accessForAdminOnly", new Class<?>[] {});
    }
    
    @Test(expected=SecurityException.class)
    public void testUserIsNotInRoleFromMasterRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler securityHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        security.securityHandler = securityHandler;
        
        security.executeSecurityChecks(RestrictedService.class, "changeEverything", new Class<?>[] {});
    }
    
    @Test
    public void testUserIsInAllRolesFromRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler securityHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER, UserRole.ADMIN);
        security.securityHandler = securityHandler;
        
        security.executeSecurityChecks(Service.class, "accessForAdminOrUser", new Class<?>[] {});

        Mockito.verify(securityHandler, Mockito.times(0)).onAccessFailure(null);
    }

    @Test
    public void testUserIsInOneOfRoleFromRestrictRoles() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler securityHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        security.securityHandler = securityHandler;

        security.executeSecurityChecks(Service.class, "accessForAdminOrUser", new Class<?>[] {});

        Mockito.verify(securityHandler, Mockito.times(0)).onAccessFailure(null);
    }

    @Test
    public void testUserIsInRoleFromRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler spySecurityHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        security.securityHandler = spySecurityHandler;

        security.executeSecurityChecks(Service.class, "accessForUserOnly", new Class<?>[] {});

        Mockito.verify(spySecurityHandler, Mockito.times(0)).onAccessFailure(null);
    }

    /**
     * Mock get role holder on security handler.
     *
     * @param securityHandler the security handler
     * @param roles the roles
     * @return the security handler
     */
    private SecurityHandler mockGetRoleHolder(SecurityHandler securityHandler, UserRole... roles) {
        SecurityHandler spySecurityHandler = Mockito.spy(securityHandler);
        User user = new User();
        for (UserRole role : roles) {
            user.getRoles().add(role);
        }

        Mockito.when(spySecurityHandler.getRoleHolder()).thenReturn(user);
        return spySecurityHandler;
    }

    @Test
    public void testUnrestrictedDoesNotRequireUser() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler securityHandler = Mockito.spy(security.securityHandler);
        security.securityHandler = securityHandler;

        security.executeSecurityChecks(RestrictedService.class, "doSimpleChange", new Class<?>[] {});

        Mockito.verify(securityHandler, Mockito.times(0)).onAccessFailure(null);
    }
    
    @Test(expected = SecurityException.class)
    public void testUserHasNoAccessToObjectsManagedByAdmin() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler securityHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        AccessHandler accessHandler = new DynamicResourcesHandler();
        Mockito.when(securityHandler.getAccessHandler()).thenReturn(accessHandler);
        security.securityHandler = securityHandler;

        security.executeSecurityChecks(ACLService.class, "save", new Class<?>[] {User.class}, new User());
    }
    
    @After
    public void cleanUp() {
        security.securityHandler = new  ACLSecurityHandler();
    }
    
}
