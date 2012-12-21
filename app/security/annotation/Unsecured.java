package security.annotation;

import java.lang.annotation.*;

/**
 * Marks unsecured methods.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Documented
public @interface Unsecured
{
}
