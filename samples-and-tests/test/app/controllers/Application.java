package controllers;

import model.Document;
import model.User;
import play.mvc.Catch;
import play.mvc.Controller;
import play.mvc.With;
import security.annotation.Access;
import security.annotation.Access.AccessType;
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

    public static void showUser(@Access(AccessType.READ) User user) {
        renderText("success");
    }

    public static void editDocument(@Access(AccessType.WRITE) Document document) {
        renderText("success");
    }

    public static void editUserById(@Access(value = AccessType.WRITE, type = User.class) Long id) {
        renderText("success");
    }

    public static void showDocumentById(@Access(value = AccessType.READ, type = Document.class) Long id) {
        renderText("success");
    }

    public static void showAndEditDocument(@Access(AccessType.READ) Document doc, @Access(AccessType.WRITE) Document doc2) {
        renderText("success");
    }

    @Catch(SecurityException.class)
    static void handleSecurityError(Throwable ex) {
        forbidden();
    }
}
