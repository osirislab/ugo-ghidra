package ugo;

import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import docking.action.DockingAction;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.Log4jErrorLogger;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

@PluginInfo(status = PluginStatus.UNSTABLE,
        packageName = UgoPlugin.PACKAGE_NAME,
        category = PluginCategoryNames.DECOMPILER,
        shortDescription = "Go Decompilation support",
        description = "Detects and updates calling convention and syntactic sugar for go binaries.",
        eventsConsumed = {ProgramActivatedPluginEvent.class}
)
public class UgoPlugin extends ProgramPlugin {
    public static final String PACKAGE_NAME = "ugo";
    public static final String MENU_ITEM = "[Ugo] Analyze";
    public static final String[] MENU_PATH = new String[]{"&Ugo", "Analyze"};


    private DockingAction ugoMenuAction;
    private Log4jErrorLogger logger;
    private Injector injector;
    private UgoActions ugoActions;

    @Inject
    public UgoPlugin(PluginTool tool) {
        super(tool, true, true);

        logger = new Log4jErrorLogger();
        logger.info(this, "Hello from ugo plugin");

        injector = setupGuice(tool);
        ugoActions = injector.getInstance(UgoActions.class);

        logger.info(this, "Initializing actions...");
        ugoActions.initializeActions();
        logger.info(this, "Actions initialized!");
    }


    private Injector setupGuice(PluginTool tool) {
        return Guice.createInjector(new UgoModule(this, tool));
    }

    @Override
    protected void programActivated(Program activatedProgram) {
        System.out.println("Hello again! Program activated");
        ugoActions.programActivated();
    }
}


// TODO: register a menu item to resymbolicate binary
// TODO: register a menu item to check if binary is golang binary
// TODO: check at beginning of analysis if binary is golang binary (and if it is, change calling convention appropriately)
// TODO: resymbolicate using pclntab