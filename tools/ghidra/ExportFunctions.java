// Export the analyzed program's functions as CSV for dos-hle-kit's find_seams.py.
//
// Usage (from analyzeHeadless):
//   -postScript ExportFunctions.java /path/to/functions.csv
//
// Output columns: address,name,size,is_thunk
// Comment lines carry the image base and entry point so the report can align addresses when
// Ghidra chooses a different base than the kit's loader.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

public class ExportFunctions extends GhidraScript {
    private static String csv(String s) {
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: ExportFunctions.java OUTPUT.csv");
            return;
        }
        File out = new File(args[0]);
        if (out.getParentFile() != null) {
            out.getParentFile().mkdirs();
        }
        Address imageBase = currentProgram.getImageBase();
        Address entry = null;
        Iterator<Address> entryPoints = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            entry = entryPoints.next();
        }
        FunctionManager functions = currentProgram.getFunctionManager();

        try (PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(out)))) {
            w.println("# backend=ghidra");
            w.println("# image_base=" + Long.toHexString(imageBase.getOffset()));
            if (entry != null) {
                w.println("# entry=" + Long.toHexString(entry.getOffset()));
            }
            w.println("address,name,size,is_thunk");
            int count = 0;
            for (Function f : functions.getFunctions(true)) {
                long size = f.getBody().getNumAddresses();
                w.printf("%08x,%s,%d,%d%n", f.getEntryPoint().getOffset(), csv(f.getName()),
                        size, f.isThunk() ? 1 : 0);
                count++;
            }
            println("ExportFunctions: wrote " + count + " functions to " + out);
        }
    }
}
