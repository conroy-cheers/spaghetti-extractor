// Export clean-room metadata for haloce-catalog import-ghidra.
//
// Usage:
//   analyzeHeadless <project-dir> <project-name> -import <binary> \
//     -postScript HaloCatalogExport.java <out.json> [sha256]
//
// This script exports addresses, labels, block ranges, CFG edges, call refs,
// and data refs only. It does not export decompiler output or instruction bytes.

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;

public class HaloCatalogExport extends GhidraScript {
    private long imageBase;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("expected output JSON path and optional sha256");
        }
        File out = new File(args[0]);
        String binarySha256 = args.length >= 2 ? args[1] : hashExecutableIfAvailable();
        imageBase = currentProgram.getImageBase().getOffset();

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
        json.append("\n}\n");

        out.getParentFile().mkdirs();
        try (FileWriter writer = new FileWriter(out)) {
            writer.write(json.toString());
        }
    }

    private void functions(StringBuilder json) {
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
            pair(json, "name", quote(function.getName()), true);
            pair(json, "calling_convention", quote(nullToUnknown(function.getCallingConventionName())), true);
            pair(json, "signature", quote("unknown"), true);
            pair(json, "subsystem", quote("unknown"), true);
            pair(json, "purity", quote("unknown"), true);
            pair(json, "side_effects", quote("unknown"), true);
            pair(json, "confidence", quote(function.isThunk() ? "medium" : "high"), false);
            json.append("}");
        }
        if (!first) {
            json.append("\n  ");
        }
        json.append("]");
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
            json.append("\n    {");
            pair(json, "rva_start", Long.toUnsignedString(start), true);
            pair(json, "rva_end", Long.toUnsignedString(end), true);
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
            json.append("\n    {");
            pair(json, "caller_rva", Long.toUnsignedString(rva(ref.getFromAddress())), true);
            pair(json, "callee_rva", Long.toUnsignedString(rva(ref.getToAddress())), true);
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
