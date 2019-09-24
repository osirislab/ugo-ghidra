package ugo;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.Log4jErrorLogger;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

import java.awt.event.KeyEvent;

@PluginInfo(status = PluginStatus.UNSTABLE,
    packageName = UgoPlugin.PACKAGE_NAME,
        category = PluginCategoryNames.DECOMPILER,
        shortDescription = "Go Decompilation support",
        description = "Detects and updates calling convention and syntactic sugar for go binaries.")
public class UgoPlugin extends ProgramPlugin {
    public static final String PACKAGE_NAME = "ugo";
    public static final String MENU_ITEM = "[Ugo] Analyze";
    public static final String[] MENU_PATH = new String[] { "&CERT", "Ugo" };

    private DockingAction ugoMenuAction;
    private Log4jErrorLogger logger;

    public UgoPlugin(PluginTool tool) {
        super(tool, true, true);

        logger = new Log4jErrorLogger();

        logger.info(this, "Hello from ugo plugin!");
        new OptionDialog("Welcome", "Welcome from ugo plugin!", OptionDialog.WARNING_MESSAGE, null).show();

        setupActions();
    }

    private void setupActions() {
        ugoMenuAction = new DockingAction(MENU_ITEM, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                logger.info(this, "Hello from action performed!");
                configureAndExecute();
            }
        };

        ugoMenuAction.setMenuBarData(new MenuData(MENU_PATH, null, PACKAGE_NAME, MenuData.NO_MNEMONIC, null));

        ugoMenuAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_AMPERSAND, 0));
        ugoMenuAction.setEnabled(false);

        tool.addAction((ugoMenuAction));
    }

    private void configureAndExecute() {
        UgoDialog dialog = new UgoDialog();
        this.tool.showDialog(dialog);
    }

    @Override
    protected void programActivated(Program activatedProgram) {
        System.out.println("Hello again! Program activated");
        ugoMenuAction.setEnabled(true);
    }
}
