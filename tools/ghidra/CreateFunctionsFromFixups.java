// Create functions at LE/LX relocation targets before ExportFunctions.java runs.
//
// Watcom/DOS games reach much of their code through function pointers stored in data. Stock
// Ghidra analysis does not always turn those pointers into functions, so this script applies
// the same rule as the kit's analyzer: a 32-bit offset relocation whose target lies in an
// executable block and is not already inside a function becomes a function.
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.SourceType;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

public class CreateFunctionsFromFixups extends GhidraScript {
    /** A plausible function prologue (Watcom frame setup, leaf function, or a jump thunk). */
    private boolean looksLikeFunctionStart(Address a) {
        if (!currentProgram.getMemory().contains(a)) {
            return false;
        }
        try {
            byte[] b = new byte[8];
            int n = currentProgram.getMemory().getBytes(a, b);
            int i = 0;
            while (i < n && b[i] >= 0x50 && b[i] <= 0x57) {
                i++;                              // push eax..edi
            }
            if (i + 2 < n && b[i] == 0x55 &&
                    ((b[i + 1] == (byte) 0x8B && b[i + 2] == (byte) 0xEC) ||
                     (b[i + 1] == (byte) 0x89 && b[i + 2] == (byte) 0xE5))) {
                return true;                      // push ebp; mov ebp, esp
            }
            if (i + 1 < n && (b[i] == (byte) 0x83 || b[i] == (byte) 0x81) &&
                    b[i + 1] == (byte) 0xEC) {
                return true;                      // sub esp, N (leaf function)
            }
            return i < n && b[i] == (byte) 0xE9;  // tail-jump thunk
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void run() throws Exception {
        AddressSet code = new AddressSet();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.isExecute() && b.isInitialized() && !b.isOverlay()) {
                code.add(b.getStart(), b.getEnd());
            }
        }
        if (code.isEmpty()) {
            println("CreateFunctionsFromFixups: no executable block");
            return;
        }

        Set<Address> targets = new LinkedHashSet<>();
        Iterator<Relocation> relocs = currentProgram.getRelocationTable().getRelocations();
        while (relocs.hasNext() && !monitor.isCancelled()) {
            Relocation r = relocs.next();
            if (r.getType() != 7 || r.getStatus() != Relocation.Status.APPLIED) {
                continue;                       // LE/LX 32-bit offset fixup
            }
            Address src = r.getAddress();
            if (!currentProgram.getMemory().contains(src)) {
                continue;
            }
            try {
                long value = currentProgram.getMemory().getInt(src) & 0xFFFFFFFFL;
                Address target = toAddr(value);
                if (code.contains(target)) {
                    targets.add(target);
                }
            } catch (Exception e) {
                // unreadable relocation site
            }
        }

        int created = 0, disassembled = 0, split = 0, skipped = 0, failed = 0;
        for (Address target : targets) {
            if (monitor.isCancelled()) {
                break;
            }
            if (getFunctionAt(target) != null) {
                continue;
            }
            Function owner = getFunctionContaining(target);
            if (owner != null) {
                // Stock analysis sometimes merges a callback or handler into its caller. Split
                // the body at the relocation target only when the target looks like a function;
                // switch-case labels and pointer tables also live inside bodies.
                if (!looksLikeFunctionStart(target)) {
                    skipped++;
                    continue;
                }
                AddressSet whole = new AddressSet(owner.getBody());
                if (target.compareTo(whole.getMinAddress()) <= 0) {
                    skipped++;
                    continue;
                }
                AddressSet before = whole.intersectRange(whole.getMinAddress(), target.subtract(1));
                AddressSet after = whole.intersectRange(target, whole.getMaxAddress());
                if (before.isEmpty() || after.isEmpty()) {
                    skipped++;
                    continue;
                }
                try {
                    owner.setBody(before);
                    currentProgram.getFunctionManager().createFunction(
                        null, target, after, SourceType.ANALYSIS);
                    split++;
                } catch (Exception e) {
                    owner.setBody(whole);
                    failed++;
                }
                continue;
            }
            if (getInstructionAt(target) == null) {
                if (getDataAt(target) != null) {
                    continue;
                }
                if (!new DisassembleCommand(target, null, true).applyTo(currentProgram, monitor)) {
                    continue;
                }
                disassembled++;
            }
            if (getInstructionAt(target) == null) {
                continue;
            }
            CreateFunctionCmd fc = new CreateFunctionCmd(null, target, null, SourceType.ANALYSIS);
            if (fc.applyTo(currentProgram, monitor)) {
                created++;
            }
        }
        println(String.format("CreateFunctionsFromFixups: %d targets, %d created, %d split from bodies, %d newly disassembled, %d skipped, %d failed",
                targets.size(), created, split, disassembled, skipped, failed));
    }
}
