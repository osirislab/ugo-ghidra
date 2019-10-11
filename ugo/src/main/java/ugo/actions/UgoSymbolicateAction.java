package ugo.actions;

import com.google.inject.Inject;
import docking.action.MenuData;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.framework.Log4jErrorLogger;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ugo.UgoPlugin;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class UgoSymbolicateAction extends ProgramContextAction {
    private static final String MENU_ITEM = "UGO_SYMBOLICATE_ACTION";
    private static final String[] MENU_PATH = new String[]{"&Analysis", "Ugo", "Symbolicate"};
    private static final MenuData menuData = new MenuData(MENU_PATH);

    private static final Lock runningLock = new ReentrantLock();

    private Log4jErrorLogger logger;

    @Inject
    public UgoSymbolicateAction(UgoPlugin plugin,
                                Log4jErrorLogger logger) {
        super(MENU_ITEM, plugin.getName());
        setMenuBarData(menuData);

        this.logger = logger;
    }

    @Override
    public void actionPerformed(ProgramActionContext actionContext) {
        boolean acquired = runningLock.tryLock();
        if (!acquired) {
            logger.error(this, "This action is already being performed");
            return;
        }
        logger.info(this, "Action performed on symbolication action");

        Program program = actionContext.getProgram();

        logger.info(this, program.getCompiler());

        SymbolTable symbolTable = program.getSymbolTable();
        logger.info(this, symbolTable.getNumSymbols());
        runningLock.unlock();
    }
}
