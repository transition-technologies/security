package security.annotation;

import java.lang.annotation.*;

import security.AclManaged;

/**
 * Specify ACL access to parameter of method by current user (logged user). The object on which the annotation is present is
 * context object of check. Examples:
 * 
 * <li>Has current user access to WRITE and READ the object of User class. Annotated object user is context object available for check:</li>
 * 
 * public void save(@Access({AccessType.WRITE, AccessType.READ}) User user)
 * 
 * <li>Has current user access to DELETE the object of class User. Annotated object (userId) is context object available for check:</li>
 * 
 * public void delete(@Access(value = { AccessType.DELETE }, type = User.class) Long userid)
 * 
 * <li>Has current user access to WRITE object of class Document. Annotated object (user) is context object available for check:</li>
 * 
 * public void addDocument(@Access(value = { AccessType.WRITE }, type = Document.class) User user, Document document)
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.PARAMETER })
@Documented
@Inherited
public @interface Access {

    public enum AccessType {
        READ,
        WRITE,
        DELETE,
        ALL
    }

    /**
     * Specify access types checks for current user to annotated object
     * 
     * @return the access types
     */
    AccessType[] value() default { AccessType.READ };

    /**
     * Type of object for which access will be checked. By default the value is AclManaged class.
     * 
     * When custom value is not set the check is done on class of annotated object.
     * 
     * <b>Required only for generic checks: has current user access (AccessType) to object of given type.</b> 
     * 
     * @return the class<? extends acl managed>
     */
    Class<? extends AclManaged> type() default AclManaged.class;

}
