package ugo;

import com.google.inject.AbstractModule;
import ghidra.framework.Log4jErrorLogger;

public class UgoModule extends AbstractModule {
    protected void configure() {
        bind(Log4jErrorLogger.class).to(Log4jErrorLogger.class);
    }
}
