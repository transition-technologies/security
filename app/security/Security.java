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
    
    public static final String DEADBOLT_HANDLER_KEY = "deadbolt.handler";

    public static final String CACHE_USER_KEY = "deadbolt.cache-user-per-request";

    public static final String CACHE_PER_REQUEST = "deadbolt.cache-user";

    private static Security security;
    
    SecurityHandler securityHandler;
    
    
    @SuppressWarnings("unchecked")
    private Security() {
        String handlerName = Play.configuration.getProperty(DEADBOLT_HANDLER_KEY);
        if (handlerName == null) {
            throw new ConfigurationException("deadbolt.handler must be defined");
        }

        try {
            Class<SecurityHandler> clazz = (Class<SecurityHandler>) Class.forName(handlerName);
            securityHandler = clazz.newInstance();
        } catch (Exception e) {
            throw new ConfigurationException(String.format("Unable to create DeadboltHandler instance: [%s]", e.getMessage()));
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
     * Checks that current user has all passed roles.
     *
     * @param roles the roles names
     * @return true, if user has all roles with given names
     */
    public boolean hasRoles(List<String> roles) {
        boolean hasAccess = false;
        RoleHolder roleHolder = getRoleHolder();
        
        if (roleHolder != null) {
            for (String roleName : roles) {
                hasAccess = containsRoleWithName(roleHolder.getRoles(), roleName);
                if (!hasAccess) {
                    break;
                }
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
    
    public boolean hasAccessForResource(Object contextObject, List<AccessType> accessTypes) {
        securityHandler.beforeRoleCheck();
        RoleHolder roleHolder = getRoleHolder();

        AccessHandler accessHandler = securityHandler.getAccessHandler();

        AccessResult accessResult = accessHandler.checkAccess(roleHolder, contextObject, accessTypes.toArray(new AccessType[accessTypes.size()]));

        return accessResult == AccessResult.ALLOWED;
    }

    /**
     * Execute role required checkif there is annotation {@link RoleRequired} on given method or its class.
     * 
     * @param method the method
     */
    private void executeRoleRequiredCheck(RoleHolder roleHolder, Method method) {
        RoleRequired roleRequired = getAnnotationFromMethodOrClass(method, RoleRequired.class);

        if (roleRequired != null) {
            
            if (roleHolder == null) {
                securityHandler.onAccessFailure("");
            } else {
                boolean hasAccess = true;
                for (String requiredRoleName : roleRequired.value()) {
                    if (!containsRoleWithName(roleHolder.getRoles(), requiredRoleName)) {
                        hasAccess = false;
                        break;
                    }
                }

                if (!hasAccess) {
                    securityHandler.onAccessFailure(method.toGenericString());
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
        Map<Object, Access> accessMap = getObjectAccessMap(Access.class, method, args);

        if (!accessMap.isEmpty()) {
            AccessResult accessResult = securityHandler.getAccessHandler().checkAccess(roleHolder, accessMap);
    
            if (accessResult == AccessResult.DENIED) {
                securityHandler.onAccessFailure("");
            }
        }
    }

    /**
     * Returns object access map, where key is the object and value the access rule.
     * 
     * @param <T> the generic type
     * @param annotationClass the annotation class
     * @param method the method
     * @param args the parameter object of method
     * @return the object access map
     */
    private <T extends Annotation> Map<Object, T> getObjectAccessMap(Class<T> annotationClass, Method method, Object... args) {
        Map<Object, T> accessMap = new HashMap<Object, T>();

        Annotation[][] parameterAnnotations = method.getParameterAnnotations();

        for (int i = 0; i < parameterAnnotations.length; i++) {
            for (int j = 0; j < parameterAnnotations[i].length; j++) {
                if (annotationClass.isInstance(parameterAnnotations[i][j])) {
                    accessMap.put(args[i], annotationClass.cast(parameterAnnotations[i][j]));
                }
            }
        }

        return accessMap;
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
            securityHandler.onAccessFailure("");
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
