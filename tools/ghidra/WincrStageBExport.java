// Export decompiler metadata for Stage B skeleton bootstrap.
//
// Usage:
//   analyzeHeadless <project-dir> <project-name> -import <binary> \
//     -postScript WincrStageBExport.java <out.json> [sha256]
//
// This script exports private dirty semantic metadata for clean-room review.
// The output may include decompiler C and p-code and must not be published.

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;

public class WincrStageBExport extends GhidraScript {
    private long imageBase;
    private DecompInterface decompiler;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("expected output JSON path and optional sha256");
        }
        File out = new File(args[0]);
        String binarySha256 = args.length >= 2 ? args[1] : hashExecutableIfAvailable();
        imageBase = currentProgram.getImageBase().getOffset();
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        ensureExternalEntryPointFunctions();

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        field(json, "schema_version", "1", true);
        field(json, "binary_sha256", quote(binarySha256), true);
        field(json, "program_name", quote(currentProgram.getName()), true);
        field(json, "image_base", Long.toUnsignedString(imageBase), true);
        json.append("  \"functions\": ");
        functions(json);
        json.append(",\n  \"basic_blocks\": ");
        blocks(json);
        json.append(",\n  \"cfg_edges\": ");
        cfgEdges(json);
        json.append(",\n  \"call_edges\": ");
        callEdges(json);
        json.append(",\n  \"data_refs\": ");
        dataRefs(json);
        json.append(",\n  \"globals\": ");
        globals(json);
        json.append("\n}\n");

        out.getParentFile().mkdirs();
        try (FileWriter writer = new FileWriter(out)) {
            writer.write(json.toString());
        }
        decompiler.dispose();
    }

    private void functions(StringBuilder json) throws Exception {
        json.append("[");
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        boolean first = true;
        for (Function function : iterator) {
            if (!first) {
                json.append(",");
            }
            first = false;
            long rva = rva(function.getEntryPoint());
            json.append("\n    {");
            pair(json, "rva", Long.toUnsignedString(rva), true);
            pair(json, "rva_end", Long.toUnsignedString(functionEndRva(function)), true);
            pair(json, "name", quote(function.getName()), true);
            pair(json, "calling_convention", quote(nullToUnknown(function.getCallingConventionName())), true);
            pair(json, "signature", quote(function.getSignature().getPrototypeString(false)), true);
            pair(json, "subsystem", quote("unknown"), true);
            pair(json, "purity", quote("unknown"), true);
            pair(json, "side_effects", quote("unknown"), true);
            pair(json, "confidence", quote(function.isThunk() ? "medium" : "high"), true);
            pair(json, "decompiler", decompilerJson(function), true);
            pair(json, "variables", variablesJson(function), true);
            pair(json, "stack_refs", stackRefsJson(function), true);
            pair(json, "global_refs", globalRefsJson(function), true);
            pair(json, "strings", stringRefsJson(function), true);
            pair(json, "callsites", callsitesJson(function), true);
            pair(json, "instructions", instructionsJson(function), true);
            pair(json, "pcode", pcodeJson(function), false);
            json.append("}");
        }
        if (!first) {
            json.append("\n  ");
        }
        json.append("]");
    }

    private void ensureExternalEntryPointFunctions() throws Exception {
        AddressIterator iterator = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            Address address = iterator.next();
            if (!inProgramMemory(address)) {
                continue;
            }
            if (currentProgram.getFunctionManager().getFunctionAt(address) != null) {
                continue;
            }
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
            String name = symbol == null ? "export_" + Long.toHexString(rva(address)) : symbol.getName();
            try {
                createFunction(address, name);
            } catch (Exception ignored) {
                // Export coverage checks will report any entrypoint Ghidra still cannot materialize.
            }
        }
    }

    private void blocks(StringBuilder json) throws Exception {
        List<CodeBlock> allBlocks = allBlocks();
        json.append("[");
        boolean first = true;
        for (CodeBlock block : allBlocks) {
            if (!first) {
                json.append(",");
            }
            first = false;
            long start = rva(block.getMinAddress());
            long end = rva(block.getMaxAddress()) + 1;
            Function function = currentProgram.getFunctionManager().getFunctionContaining(block.getMinAddress());
            json.append("\n    {");
            pair(json, "rva_start", Long.toUnsignedString(start), true);
            pair(json, "rva_end", Long.toUnsignedString(end), true);
            if (function != null) {
                pair(json, "function_rva", Long.toUnsignedString(rva(function.getEntryPoint())), true);
                pair(json, "function_name", quote(function.getName()), true);
            }
            pair(json, "instructions", blockInstructionsJson(block), true);
            pair(json, "pcode", blockPcodeJson(block), true);
            pair(json, "xrefs", blockXrefsJson(block), true);
            pair(json, "data_flow", blockDataFlowJson(block), true);
            pair(json, "semantic_summary", quote("Ghidra basic block semantic packet"), true);
            pair(json, "classification", quote("code"), true);
            pair(json, "confidence", quote("high"), false);
            json.append("}");
        }
        if (!first) {
            json.append("\n  ");
        }
        json.append("]");
    }

    private void cfgEdges(StringBuilder json) throws Exception {
        List<CodeBlock> allBlocks = allBlocks();
        json.append("[");
        boolean first = true;
        for (CodeBlock block : allBlocks) {
            CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
            while (destinations.hasNext()) {
                CodeBlockReference edge = destinations.next();
                if (!inProgramMemory(edge.getReferent()) || !inProgramMemory(edge.getDestinationAddress())) {
                    continue;
                }
                if (!first) {
                    json.append(",");
                }
                first = false;
                json.append("\n    {");
                pair(json, "from_rva", Long.toUnsignedString(rva(edge.getReferent())), true);
                pair(json, "to_rva", Long.toUnsignedString(rva(edge.getDestinationAddress())), true);
                pair(json, "edge_type", quote(edge.getFlowType().toString()), true);
                pair(json, "confidence", quote("high"), false);
                json.append("}");
            }
        }
        if (!first) {
            json.append("\n  ");
        }
        json.append("]");
    }

    private void callEdges(StringBuilder json) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferenceIterator(currentProgram.getMinAddress());
        json.append("[");
        boolean first = true;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            RefType type = ref.getReferenceType();
            if (!type.isCall()) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            Address toAddress = ref.getToAddress();
            boolean internalTarget = inProgramMemory(toAddress);
            json.append("\n    {");
            pair(json, "caller_rva", Long.toUnsignedString(rva(ref.getFromAddress())), true);
            pair(json, "callee_rva", internalTarget ? Long.toUnsignedString(rva(toAddress)) : "null", true);
            if (!internalTarget) {
                pair(json, "callee_symbol", quote(symbolName(toAddress)), true);
            }
            pair(json, "call_type", quote(type.toString()), true);
            pair(json, "confidence", quote("high"), false);
            json.append("}");
        }
        if (!first) {
            json.append("\n  ");
        }
        json.append("]");
    }

    private void dataRefs(StringBuilder json) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferenceIterator(currentProgram.getMinAddress());
        json.append("[");
        boolean first = true;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            RefType type = ref.getReferenceType();
            if (!type.isData()) {
                continue;
            }
            if (!inProgramMemory(ref.getFromAddress()) || !inProgramMemory(ref.getToAddress())) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("\n    {");
            pair(json, "from_rva", Long.toUnsignedString(rva(ref.getFromAddress())), true);
            pair(json, "to_rva", Long.toUnsignedString(rva(ref.getToAddress())), true);
            pair(json, "ref_type", quote(type.toString()), true);
            pair(json, "confidence", quote("medium"), false);
            json.append("}");
        }
        if (!first) {
            json.append("\n  ");
        }
        json.append("]");
    }

    private void globals(StringBuilder json) {
        DataIterator iterator = currentProgram.getListing().getDefinedData(true);
        json.append("[");
        boolean first = true;
        while (iterator.hasNext()) {
            Data data = iterator.next();
            Address address = data.getMinAddress();
            if (!inProgramMemory(address)) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            long start = rva(address);
            long end = start + Math.max(1, data.getLength());
            Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
            json.append("\n    {");
            pair(json, "rva", Long.toUnsignedString(start), true);
            pair(json, "rva_end", Long.toUnsignedString(end), true);
            pair(json, "name", quote(symbol == null ? "data_" + Long.toHexString(start) : symbol.getName(true)), true);
            pair(json, "data_type", quote(data.getDataType().getDisplayName()), true);
            pair(json, "symbol_type", quote(symbol == null ? "data" : symbol.getSymbolType().toString()), true);
            pair(json, "subsystem", quote("unknown"), true);
            pair(json, "confidence", quote(symbol == null ? "medium" : "high"), false);
            json.append("}");
        }
        if (!first) {
            json.append("\n  ");
        }
        json.append("]");
    }

    private List<CodeBlock> allBlocks() throws Exception {
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        AddressSetView memory = currentProgram.getMemory();
        CodeBlockIterator iterator = model.getCodeBlocksContaining(memory, monitor);
        List<CodeBlock> blocks = new ArrayList<>();
        while (iterator.hasNext()) {
            blocks.add(iterator.next());
        }
        return blocks;
    }

    private long functionEndRva(Function function) {
        Address max = function.getBody().getMaxAddress();
        if (max == null || !inProgramMemory(max)) {
            return rva(function.getEntryPoint()) + 1;
        }
        return rva(max) + 1;
    }

    private String decompilerJson(Function function) {
        StringBuilder json = new StringBuilder("{");
        try {
            DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                pair(json, "status", quote("success"), true);
                pair(json, "c", quote(results.getDecompiledFunction().getC()), false);
            } else {
                pair(json, "status", quote("error"), true);
                pair(json, "error", quote(results == null ? "decompiler returned no result" : nullToUnknown(results.getErrorMessage())), false);
            }
        } catch (Exception exc) {
            pair(json, "status", quote("error"), true);
            pair(json, "error", quote(exc.toString()), false);
        }
        json.append("}");
        return json.toString();
    }

    private String variablesJson(Function function) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        for (Parameter parameter : function.getParameters()) {
            if (!first) {
                json.append(",");
            }
            first = false;
            variableJson(json, parameter, "parameter");
        }
        for (Variable variable : function.getLocalVariables()) {
            if (!first) {
                json.append(",");
            }
            first = false;
            variableJson(json, variable, "local");
        }
        json.append("]");
        return json.toString();
    }

    private void variableJson(StringBuilder json, Variable variable, String kind) {
        json.append("{");
        pair(json, "name", quote(variable.getName()), true);
        pair(json, "kind", quote(kind), true);
        pair(json, "data_type", quote(variable.getDataType().getDisplayName()), true);
        pair(json, "storage", quote(variable.getVariableStorage().toString()), false);
        json.append("}");
    }

    private String stackRefsJson(Function function) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        for (Variable variable : function.getLocalVariables()) {
            if (!variable.isStackVariable()) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{");
            pair(json, "name", quote(variable.getName()), true);
            pair(json, "stack_offset", Integer.toString(variable.getStackOffset()), true);
            pair(json, "data_type", quote(variable.getDataType().getDisplayName()), false);
            json.append("}");
        }
        json.append("]");
        return json.toString();
    }

    private String globalRefsJson(Function function) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            for (Reference ref : instruction.getReferencesFrom()) {
                if (!ref.getReferenceType().isData() || !inProgramMemory(ref.getToAddress())) {
                    continue;
                }
                if (!first) {
                    json.append(",");
                }
                first = false;
                json.append("{");
                pair(json, "from_rva", Long.toUnsignedString(rva(ref.getFromAddress())), true);
                pair(json, "to_rva", Long.toUnsignedString(rva(ref.getToAddress())), true);
                pair(json, "ref_type", quote(ref.getReferenceType().toString()), true);
                pair(json, "symbol", quote(symbolName(ref.getToAddress())), false);
                json.append("}");
            }
        }
        json.append("]");
        return json.toString();
    }

    private String stringRefsJson(Function function) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            for (Reference ref : instruction.getReferencesFrom()) {
                if (!ref.getReferenceType().isData() || !inProgramMemory(ref.getToAddress())) {
                    continue;
                }
                Data data = currentProgram.getListing().getDefinedDataAt(ref.getToAddress());
                if (data == null || data.getValue() == null || !(data.getValue() instanceof String)) {
                    continue;
                }
                if (!first) {
                    json.append(",");
                }
                first = false;
                json.append("{");
                pair(json, "from_rva", Long.toUnsignedString(rva(ref.getFromAddress())), true);
                pair(json, "to_rva", Long.toUnsignedString(rva(ref.getToAddress())), true);
                pair(json, "value", quote((String)data.getValue()), false);
                json.append("}");
            }
        }
        json.append("]");
        return json.toString();
    }

    private String callsitesJson(Function function) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            for (Reference ref : instruction.getReferencesFrom()) {
                if (!ref.getReferenceType().isCall()) {
                    continue;
                }
                if (!first) {
                    json.append(",");
                }
                first = false;
                json.append("{");
                pair(json, "caller_rva", Long.toUnsignedString(rva(ref.getFromAddress())), true);
                pair(json, "callee_rva", inProgramMemory(ref.getToAddress()) ? Long.toUnsignedString(rva(ref.getToAddress())) : "null", true);
                pair(json, "callee_symbol", quote(symbolName(ref.getToAddress())), true);
                pair(json, "call_type", quote(ref.getReferenceType().toString()), false);
                json.append("}");
            }
        }
        json.append("]");
        return json.toString();
    }

    private String instructionsJson(Function function) {
        return instructionsJson(currentProgram.getListing().getInstructions(function.getBody(), true));
    }

    private String blockInstructionsJson(CodeBlock block) {
        return instructionsJson(currentProgram.getListing().getInstructions(blockAddressSet(block), true));
    }

    private String instructionsJson(InstructionIterator iterator) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (!inProgramMemory(instruction.getAddress())) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{");
            pair(json, "rva", Long.toUnsignedString(rva(instruction.getAddress())), true);
            pair(json, "length", Integer.toString(instruction.getLength()), true);
            pair(json, "mnemonic", quote(instruction.getMnemonicString()), true);
            pair(json, "operand_count", Integer.toString(instruction.getNumOperands()), true);
            pair(json, "flow_type", quote(instruction.getFlowType().toString()), false);
            json.append("}");
        }
        json.append("]");
        return json.toString();
    }

    private String pcodeJson(Function function) {
        return pcodeJson(currentProgram.getListing().getInstructions(function.getBody(), true));
    }

    private String blockPcodeJson(CodeBlock block) {
        return pcodeJson(currentProgram.getListing().getInstructions(blockAddressSet(block), true));
    }

    private String pcodeJson(InstructionIterator iterator) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (!inProgramMemory(instruction.getAddress())) {
                continue;
            }
            PcodeOp[] ops = instruction.getPcode();
            for (PcodeOp op : ops) {
                if (!first) {
                    json.append(",");
                }
                first = false;
                json.append("{");
                pair(json, "rva", Long.toUnsignedString(rva(instruction.getAddress())), true);
                pair(json, "op", quote(op.toString()), false);
                json.append("}");
            }
        }
        json.append("]");
        return json.toString();
    }

    private String blockXrefsJson(CodeBlock block) throws Exception {
        StringBuilder json = new StringBuilder("{");
        pair(json, "predecessors", blockSourcesJson(block), true);
        pair(json, "successors", blockDestinationsJson(block), false);
        json.append("}");
        return json.toString();
    }

    private String blockSourcesJson(CodeBlock block) throws Exception {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        CodeBlockReferenceIterator sources = block.getSources(monitor);
        while (sources.hasNext()) {
            CodeBlockReference edge = sources.next();
            if (!inProgramMemory(edge.getReferent()) || !inProgramMemory(edge.getDestinationAddress())) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{");
            pair(json, "from_rva", Long.toUnsignedString(rva(edge.getReferent())), true);
            pair(json, "to_rva", Long.toUnsignedString(rva(edge.getDestinationAddress())), true);
            pair(json, "edge_type", quote(edge.getFlowType().toString()), false);
            json.append("}");
        }
        json.append("]");
        return json.toString();
    }

    private String blockDestinationsJson(CodeBlock block) throws Exception {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
        while (destinations.hasNext()) {
            CodeBlockReference edge = destinations.next();
            if (!inProgramMemory(edge.getReferent()) || !inProgramMemory(edge.getDestinationAddress())) {
                continue;
            }
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("{");
            pair(json, "from_rva", Long.toUnsignedString(rva(edge.getReferent())), true);
            pair(json, "to_rva", Long.toUnsignedString(rva(edge.getDestinationAddress())), true);
            pair(json, "edge_type", quote(edge.getFlowType().toString()), false);
            json.append("}");
        }
        json.append("]");
        return json.toString();
    }

    private String blockDataFlowJson(CodeBlock block) {
        StringBuilder json = new StringBuilder("{");
        pair(json, "data_refs", blockDataRefsJson(block), false);
        json.append("}");
        return json.toString();
    }

    private String blockDataRefsJson(CodeBlock block) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        InstructionIterator iterator = currentProgram.getListing().getInstructions(blockAddressSet(block), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            for (Reference ref : instruction.getReferencesFrom()) {
                if (!ref.getReferenceType().isData() || !inProgramMemory(ref.getToAddress())) {
                    continue;
                }
                if (!first) {
                    json.append(",");
                }
                first = false;
                json.append("{");
                pair(json, "from_rva", Long.toUnsignedString(rva(ref.getFromAddress())), true);
                pair(json, "to_rva", Long.toUnsignedString(rva(ref.getToAddress())), true);
                pair(json, "ref_type", quote(ref.getReferenceType().toString()), false);
                json.append("}");
            }
        }
        json.append("]");
        return json.toString();
    }

    private AddressSetView blockAddressSet(CodeBlock block) {
        return new AddressSet(block.getMinAddress(), block.getMaxAddress());
    }

    private String hashExecutableIfAvailable() throws Exception {
        String executablePath = currentProgram.getExecutablePath();
        if (executablePath == null) {
            return "";
        }
        File executable = new File(executablePath);
        if (!executable.isFile()) {
            return "";
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[1024 * 1024];
        try (FileInputStream stream = new FileInputStream(executable)) {
            int read;
            while ((read = stream.read(buffer)) >= 0) {
                digest.update(buffer, 0, read);
            }
        }
        StringBuilder out = new StringBuilder();
        for (byte value : digest.digest()) {
            out.append(String.format("%02x", value));
        }
        return out.toString();
    }

    private long rva(Address address) {
        return address.getOffset() - imageBase;
    }

    private boolean inProgramMemory(Address address) {
        return currentProgram.getMemory().contains(address);
    }

    private String symbolName(Address address) {
        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) {
            return symbol.getName(true);
        }
        return address.toString();
    }

    private static String nullToUnknown(String value) {
        return value == null ? "unknown" : value;
    }

    private static void field(StringBuilder json, String name, String value, boolean comma) {
        json.append("  ").append(quote(name)).append(": ").append(value);
        json.append(comma ? ",\n" : "\n");
    }

    private static void pair(StringBuilder json, String name, String value, boolean comma) {
        json.append(quote(name)).append(": ").append(value);
        if (comma) {
            json.append(", ");
        }
    }

    private static String quote(String value) {
        if (value == null) {
            return "\"\"";
        }
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    out.append(ch);
                    break;
            }
        }
        out.append("\"");
        return out.toString();
    }
}
