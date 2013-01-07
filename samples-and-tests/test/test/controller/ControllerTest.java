package controller;

import org.junit.Test;

import model.User;
import model.UserRole;

import security.Security;

import play.mvc.Http.Request;

import play.mvc.Http.Response;
import play.test.FunctionalTest;

public class ControllerTest extends FunctionalTest {

    @Test
    public void testSecurityExceptionThrownInControllerRedirectsTo403() {
        Request request = newRequest();
        Response response = GET(request, "/listDocuments");

        assertEquals(403, response.status.intValue());
    }

    @Test
    public void testAdminContentIsVisibleByAdmin() {
        Request request = newRequest();
        request.args.put(Security.CACHE_PER_REQUEST, mockGetRoleHolder(UserRole.ADMIN));

        Response response = GET(request, "/showMixedContent");

        assertTrue("Content of response does not contains content for admin", response.out.toString().contains(
            "This is secured content for admin"));
    }

    @Test
    public void testAdminContentIsNotVisibleByGuest() {
        Request request = newRequest();
        Response response = GET(request, "/showMixedContent");

        assertFalse("Simple user can watch secured content for admin", response.out.toString().contains(
            "This is secured content for admin"));
    }
    
    @Test
    public void testAdminContentIsNotVisibleByUser() {
        Request request = newRequest();
        request.args.put(Security.CACHE_PER_REQUEST, mockGetRoleHolder(UserRole.USER));
        Response response = GET(request, "/showMixedContent");

        assertFalse("Guest can watch secured content for admin", response.out.toString().contains(
            "This is secured content for admin"));
    }
    
    @Test
    public void testSharedContentIsVisibleByUser() {
        Request request = newRequest();
        request.args.put(Security.CACHE_PER_REQUEST, mockGetRoleHolder(UserRole.USER));
        Response response = GET(request, "/showMixedContent");

        assertTrue("User cannot watch shared content", response.out.toString().contains(
            "This is shared content for admin and user"));
    }
    
    @Test
    public void testUserContentIsVisibleByUser() {
        Request request = newRequest();
        request.args.put(Security.CACHE_PER_REQUEST, mockGetRoleHolder(UserRole.USER));
        Response response = GET(request, "/showMixedContent");
       
        assertTrue("Simple user cannot watch secured content for logged user", response.out.toString().contains(
            "This is content for logged user"));
    }
    
    @Test
    public void testAdminResourceIsVisibleByAdmin() {
        Request request = newRequest();
        request.args.put(Security.CACHE_PER_REQUEST, mockGetRoleHolder(UserRole.ADMIN));

        Response response = GET(request, "/showMixedContent");

        assertTrue("Admin resource is not visible by admin", response.out.toString().contains(
            "Link to add document"));
    }
    
    @Test
    public void testAdminResourceIsNotVisibleByGuest() {
        Request request = newRequest();
        Response response = GET(request, "/showMixedContent");

        assertFalse("Admin resource is visible by guest", response.out.toString().contains(
            "Link to add document"));
    }
    
    @Test
    public void testAdminResourceIsNotVisibleByUser() {
        Request request = newRequest();
        request.args.put(Security.CACHE_PER_REQUEST, mockGetRoleHolder(UserRole.USER));
        Response response = GET(request, "/showMixedContent");

        assertFalse("Admin resource is visible by user", response.out.toString().contains(
            "Link to add document"));
    }

    private User mockGetRoleHolder(UserRole... roles) {
        User user = new User();
        for (UserRole role : roles) {
            user.getRoles().add(role);
        }

        return user;
    }
}
