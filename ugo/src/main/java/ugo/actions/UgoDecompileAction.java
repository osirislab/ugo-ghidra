package ugo.actions;

import com.google.inject.Inject;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.framework.Log4jErrorLogger;
import ugo.UgoPlugin;

public class UgoDecompileAction extends DockingAction {
    private static final String MENU_ITEM = "UGO_DECOMPILE_ACTION";
    private static final String[] MENU_PATH = new String[]{ "&Analysis", "Ugo", "Decompile" };
    private static final MenuData MENU_DATA = new MenuData(MENU_PATH);

    private Log4jErrorLogger logger;

    @Inject
    public UgoDecompileAction(UgoPlugin ugoPlugin, Log4jErrorLogger logger) {
        super(MENU_ITEM, ugoPlugin.getName());

        setMenuBarData(MENU_DATA);

        this.logger = logger;
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
    
    }
}
