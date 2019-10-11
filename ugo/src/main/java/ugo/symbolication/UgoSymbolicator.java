package ugo.symbolication;

import com.google.inject.Inject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;

public class UgoSymbolicator {

    @Inject
    public UgoSymbolicator() {

    }

    public void SymbolicateProgram(Program program) {
        SymbolTable symbolTable = program.getSymbolTable();




    }

    // TODO: pull in current program information
    // TODO: run through entire current program
    // TODO: add symbols to ghidra's database
}

// TODO: Do we want to store symbols in a file?