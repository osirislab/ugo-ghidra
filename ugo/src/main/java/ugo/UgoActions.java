package ugo;

import com.google.common.collect.ImmutableSet;
import com.google.inject.Inject;
import docking.action.DockingAction;
import ghidra.framework.plugintool.PluginTool;
import ugo.actions.UgoProcessAction;

import java.util.Set;

public class UgoActions {

    private PluginTool pluginTool;
    private Set<DockingAction> dockingActions;


    @Inject
    public UgoActions(PluginTool tool,
                      UgoProcessAction ugoProcessAction) {
        this.pluginTool = tool;
        dockingActions = ImmutableSet.of(
            ugoProcessAction
        );
    }

    public void initializeActions() {
        dockingActions.stream()
                .forEach(dockingAction -> pluginTool.addAction(dockingAction));
    }

    public void programActivated() {
        dockingActions.stream()
                .forEach(dockingAction -> dockingAction.setEnabled(true));
    }
}
