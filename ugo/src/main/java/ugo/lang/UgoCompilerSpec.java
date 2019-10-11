package ugo.lang;


import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.CompilerSpecNotFoundException;

public class UgoCompilerSpec extends BasicCompilerSpec {

    public UgoCompilerSpec(CompilerSpecDescription description, SleighLanguage language, ResourceFile cspecFile) throws CompilerSpecNotFoundException {
        super(description, language, cspecFile);
    }
}