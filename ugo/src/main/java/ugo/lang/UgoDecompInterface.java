package ugo.lang;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Program;

public class UgoDecompInterface extends DecompInterface {

    @Override
    public synchronized boolean openProgram(Program prog) {
        return super.openProgram(prog);
    }
}
