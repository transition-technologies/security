package play.modules.security

import javassist.runtime.Desc
import play.Logger
import play.PlayPlugin
import play.classloading.ApplicationClasses.ApplicationClass

/**
 *
 * @author Maciej Kujawski <m.kujawski@tt.com.pl>
 */
public class SecurityPlugin extends PlayPlugin {

    private final SecurityEnhancer enhancer = new SecurityEnhancer()

    @Override
    public void enhance(ApplicationClass applicationClass)
    throws Exception {
        enhancer.enhanceThisClass(applicationClass)
    }

    @Override
    void onLoad() {
        Logger.debug("Configuring Javassist to use context classloader");
        Desc.useContextClassLoader = true
    }

}
