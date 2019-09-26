package ugo.actions;

import com.google.inject.Inject;
import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.framework.plugintool.PluginTool;
import ugo.UgoPlugin;

import java.awt.event.KeyEvent;

public class UgoProcessAction extends DockingAction {
    private static final String MENU_ITEM = "UGO_PROCESS_ACTION";
    private static final String[] MENU_PATH = new String[]{ "&Ugo", "Process" };
    private static final MenuData menuData = new MenuData(MENU_PATH);
    private static final KeyBindingData keyBindingData = new KeyBindingData(KeyEvent.VK_AMPERSAND, KeyEvent.VK_SHIFT);

    private PluginTool pluginTool;
    private Dialog dialog;

    @Inject
    public UgoProcessAction(UgoPlugin plugin, PluginTool pluginTool) {
        super(MENU_ITEM, plugin.getName());

        this.pluginTool = pluginTool;
        this.dialog = new Dialog();

        setMenuBarData(menuData);
        setKeyBindingData(keyBindingData);
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        pluginTool.showDialog(dialog);
    }

    private class Dialog extends DialogComponentProvider {
        static final String DIALOG_TITLE = "Ugo";

        Dialog() {
            super(DIALOG_TITLE);
        }
    }
}
