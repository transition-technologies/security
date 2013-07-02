package security;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.hibernate.criterion.Restrictions;

import play.Play;
import play.exceptions.ConfigurationException;
import play.mvc.Http.Request;
import security.annotation.*;
import security.annotation.Access.AccessType;
import security.handler.AccessHandler;
import security.handler.AccessResult;
import security.handler.SecurityHandler;
import security.role.Role;
import security.role.RoleHolder;

/**
 * Perform security checks on methods and objects annotated with {@link Unsecured}, {@link RoleRequired}, {@link Restrictions},
 * {@link Access}, {@link AnyRole}. Logic of finding logged user, security access failure, acl checks is implemented
 * by {@link SecurityHandler}.
 * 
 * @author Maciej Kujawski <M.Kujawski@tt.com.pl>
 */
public class Security {
    
    public static final String SECURITY_HANDLER_KEY = "security.handler";

    public static final String CACHE_USER_KEY = "security.cache-user-per-request";

    public static final String CACHE_PER_REQUEST = "security.cache-user";

    private static Security security;
    
    SecurityHandler securityHandler;
    
    
    @SuppressWarnings("unchecked")
    private Security() {
        String handlerName = Play.configuration.getProperty(SECURITY_HANDLER_KEY);
        if (handlerName == null) {
            throw new ConfigurationException("security.handler must be defined");
        }

        try {
            Class<SecurityHandler> clazz = (Class<SecurityHandler>) Class.forName(handlerName);
            securityHandler = clazz.newInstance();
        } catch (Exception e) {
            throw new ConfigurationException(String.format("Unable to create SecurityHandler instance: [%s]", e.getMessage()));
        }
    }
    
    public static Security getInstance() {
        if (security == null) {
            security = new Security();
        }
        
        return security;
    }
    

    /**
     * Execute security checks of given method if method is not annotated with {@link Unsecured} annotation:
     * <ul>
     * <li>execute restrict check</li>
     * <li>execute role holder present check</li>
     * <li>execute access check</li>
     * </ul>.
     *
     * @param clazz the clazz
     * @param methodName the method name
     * @param paramTypes the param types
     * @param args the args
     */
    public void executeSecurityChecks(Class<?> clazz, String methodName, Class<?>[] paramTypes, Object... args) {
        Method method = getMethod(clazz, methodName, paramTypes);
        
        if (method != null && !isUnsecured(method)) {
            RoleHolder roleHolder = getRoleHolder();
            
            executeRoleRequiredCheck(roleHolder, method);
            executeAnyRoleCheck(roleHolder, method);
            executeAccessCheck(roleHolder, method, args);
        }
    }

    /**
     * Gets the method with given parameter types.
     *
     * @param clazz the clazz
     * @param methodName the method name
     * @param paramTypes the param types
     * @return the method
     */
    private Method getMethod(Class<?> clazz, String methodName, Class<?>[] paramTypes) {
        Method method = null;
        try {
            method = clazz.getDeclaredMethod(methodName, paramTypes);
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        return method;
    }
    
    /**
     * Checks that current user has at least one of passed roles.
     *
     * @param roles the roles names
     * @return true, if user has all roles with given names
     */
    public boolean hasRole(List<String> roles) {
        RoleHolder roleHolder = getRoleHolder();
        if (roleHolder == null) {
            return false;
        }

        boolean hasAccess = false;
        for (String roleName : roles) {
            hasAccess = containsRoleWithName(roleHolder.getRoles(), roleName);
            if (hasAccess) {
                break;
            }
        }

        return hasAccess;
    }
    
    /**
     * Checks if there is logged user.
     *
     * @return true, if is role holder present
     */
    public boolean isRoleHolderPresent() {
        return getRoleHolder() != null;
    }

    /**
     * Checks current user has access for given context object.
     *
     * @param contextObject the context object
     * @param accessTypes   the access types
     * @return true, if successful
     */
    public boolean hasAccess(AclManaged contextObject, AccessType[] accessTypes) {
        RoleHolder roleHolder = getRoleHolder();

        AccessHandler accessHandler = securityHandler.getAccessHandler();

        AccessResult accessResult = accessHandler.checkAccess(roleHolder, contextObject, accessTypes);

        return accessResult == AccessResult.ALLOWED;
    }

    /**
     * Checks current user has access for given context object.
     *
     * @param contextObject the context object
     * @param accessTypes   the access types
     * @return true, if successful
     */
    public boolean hasAccess(AclManaged contextObject, List<AccessType> accessTypes) {
        return hasAccess(contextObject, accessTypes.toArray(new AccessType[accessTypes.size()]));
    }

    /**
     * Checks current user has access for given context object.
     *
     * @param contextObject the context object
     * @param accessType    the access type
     * @return true, if successful
     */
    public boolean hasAccess(AclManaged contextObject, AccessType accessType) {
        return hasAccess(contextObject, new AccessType[]{accessType});
    }

    /**
     * Convert String to AccessType array that can be used to test access
     * @param value
     * @return
     */
    public AccessType toAccess(CharSequence value) {
        AccessType access = AccessType.valueOf(value.toString().toUpperCase());
        return access;
    }

    /**
     * Just to make api consistent
     *
     * @param value
     * @return
     */
    public AccessType toAccess(AccessType value) {
        return value;
    }

    /**
     * Convert List<String or AccessType> to AccessType array that can be used to test access
     *
     * @param values
     * @return
     */
    public AccessType[] toAccess(List values) {
        AccessType[] access = new AccessType[values.size()];
        int i = 0;
        for(Object value : values) {
            if(value instanceof CharSequence) {
                access[i] = toAccess((CharSequence)value);
            } else if(value instanceof AccessType) {
                access[i] = (AccessType)value;
            } else {
                throw new IllegalArgumentException("Access can only be expressed using String or " +
                        "AccessType objects. Cannot cast " + value + " to either.");
            }
            i++;
        }
        return access;
    }

    /**
     * Execute role required checkif there is annotation {@link RoleRequired} on given method or its class.
     * 
     * @param method the method
     */
    private void executeRoleRequiredCheck(RoleHolder roleHolder, Method method) {
        RoleRequired roleRequired = getAnnotationFromMethodOrClass(method, RoleRequired.class);

        if (roleRequired != null && roleRequired.value().length > 0) {
            
            if (roleHolder == null) {
                securityHandler.onAccessFailure(method);
            } else {
                boolean hasAccess = false;
                for (String requiredRoleName : roleRequired.value()) {
                    if (containsRoleWithName(roleHolder.getRoles(), requiredRoleName)) {
                        hasAccess = true;
                        break;
                    }
                }

                if (!hasAccess) {
                    securityHandler.onAccessFailure(method);
                }
            }
        }
    }

    private RoleHolder getRoleHolder() {
        securityHandler.beforeRoleCheck();

        RoleHolder roleHolder = (RoleHolder) Request.current().args.get(CACHE_PER_REQUEST);
        if (roleHolder == null) {
            roleHolder = securityHandler.getRoleHolder();
            
            if (Boolean.valueOf(Play.configuration.getProperty(CACHE_USER_KEY, "false"))) {
                Request.current().args.put(CACHE_PER_REQUEST, roleHolder);
            }
        }

        return roleHolder;
    }

    /**
     * Execute access check using {@link AccessHandler} on given args of passed method which are annotated with {@link Access} annotation.
     * 
     * @param method the method
     * @param args the args
     */
    private void executeAccessCheck(RoleHolder roleHolder, Method method, Object... args) {
        Annotation[][] parameterAnnotations = method.getParameterAnnotations();
        for (int i = 0; i < parameterAnnotations.length; i++) {
            Object contextObject = args[i];

            if (contextObject != null) {
                for (int j = 0; j < parameterAnnotations[i].length; j++) {
                    Annotation annotation = parameterAnnotations[i][j];
                    if (annotation instanceof Access) {
                        Access access = (Access) annotation;
                        contextObject = toAclManaged(contextObject, access.type());
                        AccessResult accessResult = securityHandler.getAccessHandler().checkAccess(roleHolder,
                                (AclManaged) contextObject, access.value());

                        if (accessResult == AccessResult.DENIED) {
                            securityHandler.onAccessFailure(method, (AclManaged)contextObject);
														return;
                        }
                    }
                }
            }
        }
    }

    private AclManaged toAclManaged(Object contextObject, Class<? extends AclManaged> type) {
        if (!(contextObject instanceof AclManaged)) {
            contextObject = securityHandler.getAccessHandler().toAclManaged(contextObject, type);
        }

        return (AclManaged) contextObject;
    }

    /**
     * Checks whether list of roles contains role with given requiredRoleName.
     *
     * @param roles the roles
     * @param requiredRoleName the required role name
     * @return true, if successful
     */
    private boolean containsRoleWithName(List<? extends Role> roles, String requiredRoleName) {
        boolean hasRequiredRole = false;

        for (Role role : roles) {
            if (role.getRoleName().equals(requiredRoleName)) {
                hasRequiredRole = true;
                break;
            }
        }

        return hasRequiredRole;
    }

    /**
     * Checks if there is logged user ({@link RoleHolder}) if method or class is annotated with {@link AnyRole}
     *
     * @param method the method
     */
    private void executeAnyRoleCheck(RoleHolder roleHolder, Method method) {
        AnyRole anyRole = getAnnotationFromMethodOrClass(method, AnyRole.class);

        if (anyRole != null && roleHolder == null) {
            securityHandler.onAccessFailure(method);
        }
    }

    /**
     * Checks if the method is annotated with {@link Unsecured}.
     *
     * @param method the method
     * @return true, if is unsecured
     */
    private boolean isUnsecured(Method method) {
        Unsecured unsecured = method.getAnnotation(Unsecured.class);

        return unsecured != null;
    }

    /**
     * Gets the annotation from method or class if the annotation is not present on method.
     *
     * @param <T> the generic type
     * @param method the method
     * @param annotationClass the annotation class
     * @return the annotation from method or class or null if there is no such annotation on method nor class
     */
    private <T extends Annotation> T getAnnotationFromMethodOrClass(Method method, Class<T> annotationClass) {
        T annotation = method.getAnnotation(annotationClass);

        if (annotation == null) {
            annotation = method.getDeclaringClass().getAnnotation(annotationClass);
        }

        return annotation;
    }

}
