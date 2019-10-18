package ugo.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;

/**
 * A base class for {@link DecompilePlugin} actions that handles checking whether the
 * decompiler is busy.   Each action is responsible for deciding its enablement via
 * {@link #isEnabledForDecompilerContext(DecompilerActionContext)}.  Each action must implement
 * {@link #decompilerActionPerformed(DecompilerActionContext)} to complete its work.
 *
 * <p>This parent class uses the {@link DecompilerActionContext} to check for the decompiler's
 * busy status.  If the decompiler is busy, then the action will report that it is enabled.  We
 * do this so that any keybindings registered for this action will get consumed and not passed up
 * to the global context.   Then, if the action is executed, this class does not call the child
 * class, but will instead show an information message indicating that the decompiler is busy.
 */
public abstract class UgoAbstractDecompilerAction extends DockingAction {

    public UgoAbstractDecompilerAction(String name) {
        super(name, DecompilePlugin.class.getSimpleName());
    }

    @Override
    public boolean isValidContext(ActionContext context) {
        return context instanceof DecompilerActionContext;
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
        return decompilerContext.checkActionEnablement(() -> {
            return isEnabledForDecompilerContext(decompilerContext);
        });
    }

    @Override
    public void actionPerformed(ActionContext context) {
        DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
        decompilerContext.performAction(() -> {
            decompilerActionPerformed(decompilerContext);
        });
    }

    /**
     * Subclasses return true if they are enabled for the given context
     *
     * @param context the context
     * @return true if enabled
     */
    protected abstract boolean isEnabledForDecompilerContext(DecompilerActionContext context);

    /**
     * Subclasses will perform their work in this method
     * @param context the context
     */
    protected abstract void decompilerActionPerformed(DecompilerActionContext context);
}
