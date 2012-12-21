package play.modules.security

import java.lang.annotation.Annotation

import javassist.*
import play.Logger
import play.classloading.ApplicationClasses.ApplicationClass
import play.classloading.enhancers.Enhancer

import static javassist.Modifier.*

/**
 * Playframework class enhancer adding security checks for methods annotated or methods that are in class 
 * annotated with annotations from security.annotations package.
 * 
 * Security checks are defined by logic of {@link Security}.
 *
 * @author Maciej Kujawski <m.kujawski@tt.com.pl>
 */
public class SecurityEnhancer extends Enhancer {

    /**
     * Check if class should be enhanced and add security check as first step to all methods
     * that requires security check.
     *
     * @param ac class to enhance
     * @throws Exception
     */
    @Override
    public void enhanceThisClass(ApplicationClass ac) throws Exception {
        CtClass clazz = makeClass(ac)

        final boolean shouldRebuildClass = false
        def methods = clazz.getDeclaredMethods()
        methods.grep({shouldEnhance(clazz, it)}).each { method ->
            Logger.debug "Injecting validation code in method: ${method.longName}"
            enhanceMethod(clazz, method)
            shouldRebuildClass = true
        }
            
            
        if (shouldRebuildClass) {
            clazz.rebuildClassFile()

            ac.enhancedByteCode = clazz.toBytecode();
            clazz.defrost();
        }
    }

    /**
     * Insert security.Security.getInstance().executeSecurityChecks call in the beginning of a method
     * @param clazz
     * @param method
     * @return
     */
    private def enhanceMethod(CtClass clazz, CtMethod method) {
        Logger.debug "Enhancing: ${method.longName}"
        method.insertBefore("security.Security.getInstance().executeSecurityChecks(${clazz.name}.class, \"${method.name}\", \$sig, \$args);")
    }

    /**
     * Check if method should be enhanced
     *
     * @param clazz
     * @param method
     * @return
     */
    private boolean shouldEnhance(CtClass clazz, CtMethod method) {
        boolean isAnnotation = false;
        
        isAnnotation = (hasAnnotation(method, "security.annotation.RoleRequired")
        || hasAnnotation(method, "security.annotation.AnyRole")
        || hasAnnotation(method, "security.annotation.Unsecured")
        || hasAnnotation(clazz, "security.annotation.RoleRequired")
        || hasAnnotation(clazz, "security.annotation.AnyRole")
        || hasAnnotation(clazz, "security.annotation.Unsecured"))
 
        if (!isAnnotation) {
            isAnnotation = !method.getParameterAnnotations().flatten().grep({((Annotation)it).annotationType().getName().equals("security.annotation.Access")}).empty
        }
        
        return isAnnotation
    }
}
