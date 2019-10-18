package ugo.actions;

import com.google.inject.Inject;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.Log4jErrorLogger;
import ghidra.framework.plugintool.PluginTool;
import ugo.UgoPlugin;

public class UgoDecompileAction extends DockingAction {
    private static final String MENU_ITEM = "UGO_DECOMPILE_ACTION";
    private static final String[] MENU_PATH = new String[]{ "&Analysis", "Ugo", "Decompile" };
    private static final MenuData MENU_DATA = new MenuData(MENU_PATH);

    private PluginTool pluginTool;
    private Log4jErrorLogger logger;

    @Inject
    public UgoDecompileAction(PluginTool pluginTool, UgoPlugin ugoPlugin, Log4jErrorLogger logger) {
        super(MENU_ITEM, ugoPlugin.getName());

        setMenuBarData(MENU_DATA);

        this.pluginTool = pluginTool;
        this.logger = logger;
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        logger.info(this, "Go decompiler running");

//        DecompilerProvider decompilerProvider = new DecompilerProvider();
    }
}
