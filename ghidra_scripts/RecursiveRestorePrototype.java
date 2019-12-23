// We do recursive descent to retrieve parameters for functions
// Go to main.main() and let it rip <beyblade>
//@author pa_ssion and tnek
//@category Analysis
//@keybinding
//@menupath Anaylsis.[UGO] Restore Parameters
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.*;

public class RecursiveRestorePrototype extends GhidraScript {

    public void run() throws Exception {

        Function function = currentProgram.getFunctionManager().getFunctionContaining(this.currentAddress);

        Set<Function> visited = new HashSet<>();
        this.RecursiveRestorePrototype(function, visited);

    }

    private void RecursiveRestorePrototype(Function function, Set<Function> visited) {
        if (visited.contains(function)) return;

        this.RestorePrototype(function);

        visited.add(function);
        Set<Function> called = function.getCalledFunctions(monitor);
        for (Function f : called) {
            if (monitor.isCancelled()) break;
            this.RecursiveRestorePrototype(f, visited);
        }
    }

    private void RestorePrototype(Function function) {
        Listing listing = currentProgram.getListing();
        ReferenceManager refMan = currentProgram.getReferenceManager();
        AddressSetView addressSetView = function.getBody();

        InstructionIterator iter = listing.getInstructions(addressSetView, true);
        // Find first SUB RSP
        Scalar stackOffset = new Scalar(0, 0L, true);
        while(iter.hasNext()) {
            Instruction curr = iter.next();

            if (curr.getMnemonicString().equals("SUB")) {
                Object[] objs = curr.getOpObjects(1);
                if (!(objs[0] instanceof Scalar)) return;
                stackOffset = (Scalar) objs[0];
                break;
            }
        }

        if (!iter.hasNext()) return;
        if (stackOffset.getValue() == 0) return;

        List<Scalar> arguments = new ArrayList<>();
        while(iter.hasNext()) {
            if (monitor.isCancelled()) break;
            Instruction curr = iter.next();

            try {

                Object[] opObjects = curr.getOpObjects(1);
                if (opObjects.length == 0) continue;

                if (opObjects.length < 2) continue; // we need something with RSP+offset

                Object reg = opObjects[0];
                if (!(reg instanceof Register) || !reg.toString().equals("RSP")) continue;

                if (!(opObjects[1] instanceof Scalar)) continue; // RSP + register is hard
                Scalar offset = (Scalar) opObjects[1];

                if (offset.compareTo(stackOffset) > 0) {
//                    printf("%s is reference to argument %d\n", curr.toString(), (offset.getValue() - stackOffset.getValue()) / 8);
                    arguments.add(offset);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        Collections.sort(arguments);

        if (arguments.size() > 0) {
            function.setCustomVariableStorage(true);

            List<Variable> parameters = new ArrayList<>();
            for (Scalar off : arguments) {
                try {
                    Variable v = new ParameterImpl(String.format("arg%d", (off.getValue() - stackOffset.getValue()) / 8), DataType.DEFAULT, (int)(off.getValue() - stackOffset.getValue()), currentProgram);
                    parameters.add(v);
                } catch (InvalidInputException e) {
                    e.printStackTrace();
                }
            }

            try {
                function.replaceParameters(
                        parameters,
                        Function.FunctionUpdateType.CUSTOM_STORAGE,
                        true,
                        SourceType.ANALYSIS
                );
            } catch (InvalidInputException e) {
                e.printStackTrace();
            } catch (DuplicateNameException e) {
                e.printStackTrace();
            }
        }
    }
}

