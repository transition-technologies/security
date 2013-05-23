package security.annotation;

import java.lang.annotation.*;

import security.AclManaged;

/**
 * Specify ACL access to parameter of method by current user (logged user). The object on which the annotation is present is
 * context object of check. Examples:
 * <p/>
 * <li>Has current user access to WRITE and READ the object of User class. Annotated object user is context object available for check:</li>
 * <p/>
 * public void save(@Access({AccessType.WRITE, AccessType.READ}) User user)
 * <p/>
 * <li>Has current user access to DELETE the object of class User. Annotated object (userId) is context object available for check:</li>
 * <p/>
 * public void delete(@Access(value = { AccessType.DELETE }, type = User.class) Long userid)
 * <p/>
 * <li>Has current user access to WRITE object of class Document. Annotated object (user) is context object available for check:</li>
 * <p/>
 * public void addDocument(@Access(value = { AccessType.WRITE }, type = Document.class) User user, Document document)
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.PARAMETER})
@Documented
@Inherited
public @interface Access {

    public enum AccessType {
        READ((short) 1),
        WRITE((short) 2),
        DELETE((short) 4),
        ALL((short) 7);

        private final short code;

        private AccessType(short code) {
            this.code = code;
        }

        public short getCode() {
            return code;
        }
    }

    /**
     * Specify access types checks for current user to annotated object
     *
     * @return the access types
     */
    AccessType[] value() default {AccessType.READ};

    /**
     * Type of object for which access will be checked. By default the value is AclManaged class.
     * <p/>
     * When custom value is not set the check is done on class of annotated object.
     * <p/>
     * <b>Required only for generic checks: has current user access (AccessType) to object of given type.</b>
     *
     * @return the class<? extends acl managed>
     */
    Class<? extends AclManaged> type() default AclManaged.class;

}
