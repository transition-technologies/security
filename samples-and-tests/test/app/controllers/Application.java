package controllers;

import play.mvc.Controller;
import play.mvc.With;
import security.annotation.AnyRole;
import security.controller.SecurityController;

@With(SecurityController.class)
public class Application extends Controller {

    public static void index() {
        render();
    }

    public static void controllerMethod(String param) {

    }

    @AnyRole
    public static void listDocuments() {
        renderText("dadssad");
    }
    
    public static void showMixedContent() {
        render();
    }

}
