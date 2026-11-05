// Dumps decompiled code needed to add a native "entity.blip" action to libgtav.so
//@category GTAV

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExtractBlipInfo extends GhidraScript {

    // virtual address (without Ghidra image base) of Java_..._TrainerBridge_nativeSubmit
    private static final long NATIVE_SUBMIT_VA = 0x213b928L;

    private static final String[] TARGET_STRINGS = new String[] {
        "BLIP_OTHPLYR",
        "Invalid key for blip. Blip key=%d",
        "friend_blip",
        "SET_BLIP_NAME_TO_PLAYER_NAME",
        "START_BLIP_FLASHING",
        "CREATE_PED",
        "player_zero"
    };

    private DecompInterface ifc;
    private PrintWriter out;
    private final Set<Long> done = new HashSet<Long>();
    private long base;

    @Override
    protected void run() throws Exception {
        String outPath = "/tmp/decomp.txt";
        String[] args = getScriptArgs();
        if (args != null && args.length > 0) {
            outPath = args[0];
        }
        out = new PrintWriter(new FileWriter(outPath));
        base = currentProgram.getImageBase().getOffset();

        ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        out.println("// image base = 0x" + Long.toHexString(base));
        out.println("// all addresses below are printed as VA (Ghidra address minus image base)");

        Address ns = currentProgram.getImageBase().add(NATIVE_SUBMIT_VA);
        Function submit = getFunctionAt(ns);
        if (submit == null) {
            disassemble(ns);
            submit = createFunction(ns, "nativeSubmit");
        }
        if (submit == null) {
            out.println("// ERROR: could not create function at nativeSubmit");
            out.close();
            return;
        }

        // Phase 1: nativeSubmit + callees
        dump(submit, "PHASE1 nativeSubmit");
        Set<Function> callees = submit.getCalledFunctions(monitor);
        for (Function c : callees) {
            if (c.isThunk() || c.isExternal()) continue;
            if (c.getBody().getNumAddresses() > 20000) continue;
            dump(c, "PHASE1 callee of nativeSubmit");
        }

        // Phase 2: functions sharing the globals nativeSubmit touches (queue / consumer)
        Map<Long, Integer> score = new HashMap<Long, Integer>();
        Map<Long, Function> byEntry = new HashMap<Long, Function>();
        Set<Long> globals = new HashSet<Long>();
        for (Instruction ins : currentProgram.getListing().getInstructions(submit.getBody(), true)) {
            for (Reference r : ins.getReferencesFrom()) {
                if (!r.getReferenceType().isData()) continue;
                Address to = r.getToAddress();
                MemoryBlock b = currentProgram.getMemory().getBlock(to);
                if (b == null || !b.isWrite() || b.isExecute()) continue;
                globals.add(to.getOffset());
            }
        }
        out.println("\n// nativeSubmit touches " + globals.size() + " writable globals");
        for (Long g : globals) {
            Address ga = currentProgram.getImageBase().getNewAddress(g);
            out.println("//   global va=0x" + Long.toHexString(g - base));
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(ga);
            Set<Long> seenForThisGlobal = new HashSet<Long>();
            while (it.hasNext()) {
                Reference r = it.next();
                Function f = getFunctionContaining(r.getFromAddress());
                if (f == null || f.equals(submit)) continue;
                long e = f.getEntryPoint().getOffset();
                if (!seenForThisGlobal.add(e)) continue;
                byEntry.put(e, f);
                Integer s = score.get(e);
                score.put(e, s == null ? 1 : s + 1);
            }
        }
        List<Long> ranked = new ArrayList<Long>(score.keySet());
        ranked.sort((a, b) -> score.get(b) - score.get(a));
        int n = 0;
        for (Long e : ranked) {
            if (n >= 30) break;
            Function f = byEntry.get(e);
            if (f.getBody().getNumAddresses() > 40000) continue;
            dump(f, "PHASE2 shares " + score.get(e) + " globals with nativeSubmit");
            n++;
        }

        // Phase 3: functions referencing blip / ped strings
        for (String target : TARGET_STRINGS) {
            int count = 0;
            for (Data d : currentProgram.getListing().getDefinedData(true)) {
                if (monitor.isCancelled()) break;
                if (!d.hasStringValue()) continue;
                Object v = d.getValue();
                if (!(v instanceof String)) continue;
                if (!target.equals(v)) continue;
                out.println("\n// string \"" + target + "\" at va=0x"
                    + Long.toHexString(d.getAddress().getOffset() - base));
                ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                while (it.hasNext() && count < 6) {
                    Reference r = it.next();
                    Function f = getFunctionContaining(r.getFromAddress());
                    if (f == null) continue;
                    if (f.getBody().getNumAddresses() > 40000) continue;
                    dump(f, "PHASE3 references \"" + target + "\"");
                    count++;
                }
                break;
            }
        }

        out.println("\n// DONE");
        out.close();
    }

    private void dump(Function f, String why) {
        if (f == null) return;
        long e = f.getEntryPoint().getOffset();
        if (!done.add(e)) return;
        out.println("\n// ===== " + f.getName() + " va=0x" + Long.toHexString(e - base)
            + " size=" + f.getBody().getNumAddresses() + " : " + why + " =====");
        try {
            DecompileResults r = ifc.decompileFunction(f, 180, monitor);
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                out.println(r.getDecompiledFunction().getC());
            } else {
                out.println("// decompile failed");
            }
        } catch (Exception ex) {
            out.println("// decompile exception: " + ex);
        }
        out.flush();
    }
}
