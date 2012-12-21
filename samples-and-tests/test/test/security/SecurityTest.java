package security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import security.handler.SecurityHandler;

import security.handler.AccessHandler;

import exception.SecurityException;
import model.User;
import model.UserRole;
import play.test.UnitTest;
import services.ACLService;
import services.RestrictedService;
import services.Service;

public class SecurityTest extends UnitTest {

    Security security;
    
    @Before
    public void setUpMocks() {
        SecurityHandler deadboltHandler = new ACLSecurityHandler();
        
        security = Security.getInstance();
        security.securityHandler = deadboltHandler;
    }
    
    @Test(expected=SecurityException.class)
    public void testRoleHolderPresent() throws java.lang.SecurityException, NoSuchMethodException {
        security.executeSecurityChecks(Service.class, "securedMethod", new Class<?>[] {});
    }

    @Test(expected=SecurityException.class)
    public void testUserIsNotInRoleFromRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler deadboltHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        security.securityHandler = deadboltHandler;
        
        security.executeSecurityChecks(Service.class, "accessForAdminOnly", new Class<?>[] {});
    }
    
    @Test(expected=SecurityException.class)
    public void testUserIsNotInRoleFromMasterRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler deadboltHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        security.securityHandler = deadboltHandler;
        
        security.executeSecurityChecks(RestrictedService.class, "changeEverything", new Class<?>[] {});
    }
    
    @Test
    public void testUserIsInAllRolesFromRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler deadboltHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER, UserRole.ADMIN);
        security.securityHandler = deadboltHandler;
        
        security.executeSecurityChecks(Service.class, "accessForAdminAndUser", new Class<?>[] {});
        
        Mockito.verify(deadboltHandler, Mockito.times(0)).onAccessFailure(Mockito.anyString());
    }
    
    @Test
    public void testUserIsInRoleFromRestrictRole() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler spyDeadboltHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        security.securityHandler = spyDeadboltHandler;
  
        security.executeSecurityChecks(Service.class, "accessForUserOnly", new Class<?>[] {});
        
        Mockito.verify(spyDeadboltHandler, Mockito.times(0)).onAccessFailure(Mockito.anyString());
    }

    /**
     * Mock get role holder on deadbolt handler.
     *
     * @param deadboltHandler the deadbolt handler
     * @param roles the roles
     * @return the deadbolt handler
     */
    private SecurityHandler mockGetRoleHolder(SecurityHandler deadboltHandler, UserRole... roles) {
        SecurityHandler spyDeadboltHandler = Mockito.spy(deadboltHandler);
        User user = new User();
        for (UserRole role : roles) {
            user.getRoles().add(role);
        }
        
        Mockito.when(spyDeadboltHandler.getRoleHolder()).thenReturn(user);
        return spyDeadboltHandler;
    }
    
    @Test
    public void testUnrestrictedDoesNotRequireUser() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler deadboltHandler = Mockito.spy(security.securityHandler);
        security.securityHandler = deadboltHandler;
        
        security.executeSecurityChecks(RestrictedService.class, "doSimpleChange", new Class<?>[] {});
        
        Mockito.verify(deadboltHandler, Mockito.times(0)).onAccessFailure(Mockito.anyString());
    }
    
    @Test(expected = SecurityException.class)
    public void testUserHasNoAccessToObjectsManagedByAdmin() throws java.lang.SecurityException, NoSuchMethodException {
        SecurityHandler deadboltHandler = mockGetRoleHolder(security.securityHandler, UserRole.USER);
        AccessHandler accessHandler = new DynamicResourcesHandler();
        Mockito.when(deadboltHandler.getAccessHandler()).thenReturn(accessHandler);
        security.securityHandler = deadboltHandler;

        security.executeSecurityChecks(ACLService.class, "save", new Class<?>[] {User.class}, new User());
    }
    
    @After
    public void cleanUp() {
        security.securityHandler = new  ACLSecurityHandler();
    }
    
}
