package ugo;

import ghidra.framework.Log4jErrorLogger;
import ghidra.framework.plugintool.util.PluginPackage;

public class UgoPluginPackage extends PluginPackage {
    private static final String PACKAGE_NAME = "ugo";
    private static final String DESCRIPTION = "A go decompiler utility.";
    private static final int priority = MISCELLANIOUS_PRIORITY;
    private Log4jErrorLogger logger;

    public UgoPluginPackage() {
        super(PACKAGE_NAME, null, DESCRIPTION, priority);

        logger = new Log4jErrorLogger();

        setupAndConfigure();
    }

    private void setupAndConfigure() {
        logger.info(this, "Hello from ugo package plugin!");
    }
}
