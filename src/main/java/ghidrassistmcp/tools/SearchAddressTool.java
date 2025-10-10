/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for finding references/pointers to specific addresses.
 */
public class SearchAddressTool implements McpTool {

    @Override
    public String getName() {
        return "search_address";
    }

    @Override
    public String getDescription() {
        return "Search for references/pointers to a specific address or address range";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "target_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "range_size", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "include_direct", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "include_memory", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "include_offsets", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("target_address"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPPlugin plugin) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String targetAddrStr = (String) arguments.get("target_address");
        Integer rangeSize = (Integer) arguments.get("range_size");
        Boolean includeDirect = (Boolean) arguments.get("include_direct");
        Boolean includeMemory = (Boolean) arguments.get("include_memory");
        Boolean includeOffsets = (Boolean) arguments.get("include_offsets");
        Integer limit = (Integer) arguments.get("limit");

        if (targetAddrStr == null || targetAddrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("target_address parameter is required")
                .build();
        }

        // Parse target address
        Address targetAddr = currentProgram.getAddressFactory().getAddress(targetAddrStr);
        if (targetAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + targetAddrStr)
                .build();
        }

        // Setup search parameters
        int maxResults = limit != null ? limit : 100;
        boolean searchDirect = includeDirect != null ? includeDirect : true;
        boolean searchMemory = includeMemory != null ? includeMemory : true;
        boolean searchOffsets = includeOffsets != null ? includeOffsets : false;

        // Perform search
        List<SearchResult> results = searchForAddress(currentProgram, targetAddr, rangeSize,
                                                      searchDirect, searchMemory, searchOffsets, maxResults);

        // Format results
        StringBuilder output = new StringBuilder();
        output.append(String.format("Searching for references to address: %s", targetAddr));
        if (rangeSize != null && rangeSize > 0) {
            Address endAddr = targetAddr.add(rangeSize - 1);
            output.append(String.format(" - %s (%d bytes)", endAddr, rangeSize));
        }
        output.append("\n");
        output.append(String.format("Search scope: %s%s%s\n",
            searchDirect ? "direct refs" : "",
            searchMemory ? (searchDirect ? ", memory pointers" : "memory pointers") : "",
            searchOffsets ? ", offsets" : ""));
        output.append(String.format("\nFound %d references:\n\n", results.size()));

        // Group results by type
        List<SearchResult> codeRefs = new ArrayList<>();
        List<SearchResult> dataRefs = new ArrayList<>();
        List<SearchResult> memoryRefs = new ArrayList<>();

        for (SearchResult result : results) {
            if ("Code".equals(result.type)) {
                codeRefs.add(result);
            } else if ("Data".equals(result.type)) {
                dataRefs.add(result);
            } else {
                memoryRefs.add(result);
            }
        }

        // Output code references
        if (!codeRefs.isEmpty()) {
            output.append("=== Code References ===\n");
            for (SearchResult result : codeRefs) {
                output.append(String.format("@ %s: %s\n", result.fromAddress, result.description));
                if (result.context != null) {
                    output.append(String.format("  %s\n", result.context));
                }
            }
            output.append("\n");
        }

        // Output data references
        if (!dataRefs.isEmpty()) {
            output.append("=== Data References ===\n");
            for (SearchResult result : dataRefs) {
                output.append(String.format("@ %s: %s\n", result.fromAddress, result.description));
                if (result.context != null) {
                    output.append(String.format("  %s\n", result.context));
                }
            }
            output.append("\n");
        }

        // Output memory references
        if (!memoryRefs.isEmpty()) {
            output.append("=== Memory Pointers ===\n");
            for (SearchResult result : memoryRefs) {
                output.append(String.format("@ %s: %s\n", result.fromAddress, result.description));
                if (result.context != null) {
                    output.append(String.format("  %s\n", result.context));
                }
            }
            output.append("\n");
        }

        if (results.size() == maxResults) {
            output.append(String.format("Showing first %d references (limit reached)", maxResults));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }

    private List<SearchResult> searchForAddress(Program program, Address targetAddr, Integer rangeSize,
                                               boolean searchDirect, boolean searchMemory, boolean searchOffsets,
                                               int maxResults) {
        List<SearchResult> results = new ArrayList<>();

        // Create address range if specified
        Address endAddr = targetAddr;
        if (rangeSize != null && rangeSize > 1) {
            try {
                endAddr = targetAddr.add(rangeSize - 1);
            } catch (Exception e) {
                endAddr = targetAddr;
            }
        }

        // Search direct references
        if (searchDirect) {
            searchDirectReferences(program, targetAddr, endAddr, searchOffsets, results, maxResults);
        }

        // Search memory for pointer values
        if (searchMemory && results.size() < maxResults) {
            searchMemoryPointers(program, targetAddr, endAddr, results, maxResults);
        }

        return results;
    }

    private void searchDirectReferences(Program program, Address startAddr, Address endAddr,
                                       boolean includeOffsets, List<SearchResult> results, int maxResults) {
        ReferenceManager refMgr = program.getReferenceManager();

        // Search references to each address in range
        Address currentAddr = startAddr;
        while (currentAddr != null && currentAddr.compareTo(endAddr) <= 0 && results.size() < maxResults) {
            ReferenceIterator refIter = refMgr.getReferencesTo(currentAddr);

            while (refIter.hasNext() && results.size() < maxResults) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();

                SearchResult result = new SearchResult();
                result.fromAddress = fromAddr.toString();
                result.targetAddress = currentAddr.toString();
                result.referenceType = ref.getReferenceType().getName();

                // Determine if from code or data
                Instruction instr = program.getListing().getInstructionAt(fromAddr);
                if (instr != null) {
                    result.type = "Code";
                    result.description = String.format("%s -> %s (%s)",
                        instr.toString(), currentAddr, ref.getReferenceType().getName());
                    result.context = getFunctionContext(program, fromAddr);
                } else {
                    Data data = program.getListing().getDefinedDataAt(fromAddr);
                    if (data != null) {
                        result.type = "Data";
                        result.description = String.format("%s pointer -> %s",
                            data.getDataType().getName(), currentAddr);

                        // Get symbol if exists
                        var symbol = program.getSymbolTable().getPrimarySymbol(fromAddr);
                        if (symbol != null) {
                            result.context = "Symbol: " + symbol.getName();
                        }
                    } else {
                        result.type = "Unknown";
                        result.description = String.format("Reference -> %s (%s)",
                            currentAddr, ref.getReferenceType().getName());
                    }
                }

                results.add(result);
            }

            // Move to next address in range
            try {
                currentAddr = currentAddr.add(1);
                if (currentAddr.compareTo(endAddr) > 0) {
                    break;
                }
            } catch (Exception e) {
                break;
            }
        }

        // If including offsets, also search for instructions that compute addresses
        if (includeOffsets && results.size() < maxResults) {
            searchOffsetReferences(program, startAddr, endAddr, results, maxResults);
        }
    }

    private void searchOffsetReferences(Program program, Address startAddr, Address endAddr,
                                       List<SearchResult> results, int maxResults) {
        Listing listing = program.getListing();
        var instrIter = listing.getInstructions(true);

        long targetValue = startAddr.getOffset();
        long rangeEnd = endAddr.getOffset();

        while (instrIter.hasNext() && results.size() < maxResults) {
            Instruction instr = instrIter.next();
            Address addr = instr.getAddress();
            if (instr == null) continue;

            // Check operands for values that could be offsets to our target
            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                Object[] opObjs = instr.getOpObjects(i);
                for (Object obj : opObjs) {
                    if (obj instanceof Scalar) {
                        Scalar scalar = (Scalar) obj;
                        long value = scalar.getUnsignedValue();

                        // Check if this could be an offset calculation
                        if (value >= targetValue - 0x1000 && value <= rangeEnd + 0x1000) {
                            long offset = value - targetValue;
                            if (offset != 0 && Math.abs(offset) <= 0x1000) {
                                SearchResult result = new SearchResult();
                                result.fromAddress = addr.toString();
                                result.targetAddress = startAddr.toString();
                                result.type = "Code";
                                result.referenceType = "Offset";
                                result.description = String.format("%s (possible offset %+d from %s)",
                                    instr.toString(), offset, startAddr);
                                result.context = getFunctionContext(program, addr);
                                results.add(result);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    private void searchMemoryPointers(Program program, Address targetAddr, Address endAddr,
                                     List<SearchResult> results, int maxResults) {
        Memory memory = program.getMemory();
        int pointerSize = program.getDefaultPointerSize();
        boolean isBigEndian = program.getLanguage().isBigEndian();

        // Search for pointer values in memory
        long targetValue = targetAddr.getOffset();
        byte[] pattern = new byte[pointerSize];

        // Create byte pattern for pointer
        for (int i = 0; i < pointerSize; i++) {
            if (isBigEndian) {
                pattern[pointerSize - 1 - i] = (byte) ((targetValue >> (i * 8)) & 0xFF);
            } else {
                pattern[i] = (byte) ((targetValue >> (i * 8)) & 0xFF);
            }
        }

        try {
            Address addr = memory.findBytes(memory.getMinAddress(), pattern, null, true, null);

            while (addr != null && results.size() < maxResults) {
                // Check if this is already covered by direct references
                boolean alreadyFound = false;
                for (SearchResult existing : results) {
                    if (existing.fromAddress.equals(addr.toString())) {
                        alreadyFound = true;
                        break;
                    }
                }

                if (!alreadyFound) {
                    SearchResult result = new SearchResult();
                    result.fromAddress = addr.toString();
                    result.targetAddress = targetAddr.toString();
                    result.type = "Memory";
                    result.referenceType = "Pointer";

                    // Check if this is in defined data
                    Data data = program.getListing().getDefinedDataAt(addr);
                    if (data != null) {
                        result.description = String.format("%s pointer -> %s",
                            data.getDataType().getName(), targetAddr);
                    } else {
                        result.description = String.format("Raw %d-byte pointer -> %s",
                            pointerSize, targetAddr);
                    }

                    // Add context
                    result.context = getMemoryContext(program, addr);
                    results.add(result);
                }

                // Search for next occurrence
                addr = memory.findBytes(addr.add(1), pattern, null, true, null);
            }

            // If searching a range, also search for other addresses in range
            if (!targetAddr.equals(endAddr)) {
                Address currentTarget = targetAddr.add(1);
                while (currentTarget != null && currentTarget.compareTo(endAddr) <= 0 && results.size() < maxResults) {
                    searchSingleMemoryPointer(memory, program, currentTarget, isBigEndian, pointerSize, results, maxResults);
                    try {
                        currentTarget = currentTarget.add(1);
                    } catch (Exception e) {
                        break;
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error searching memory for pointers", e);
        }
    }

    private void searchSingleMemoryPointer(Memory memory, Program program, Address targetAddr,
                                          boolean isBigEndian, int pointerSize,
                                          List<SearchResult> results, int maxResults) {
        long targetValue = targetAddr.getOffset();
        byte[] pattern = new byte[pointerSize];

        for (int i = 0; i < pointerSize; i++) {
            if (isBigEndian) {
                pattern[pointerSize - 1 - i] = (byte) ((targetValue >> (i * 8)) & 0xFF);
            } else {
                pattern[i] = (byte) ((targetValue >> (i * 8)) & 0xFF);
            }
        }

        try {
            Address addr = memory.findBytes(memory.getMinAddress(), pattern, null, true, null);
            if (addr != null && results.size() < maxResults) {
                SearchResult result = new SearchResult();
                result.fromAddress = addr.toString();
                result.targetAddress = targetAddr.toString();
                result.type = "Memory";
                result.referenceType = "Pointer";
                result.description = String.format("Raw pointer -> %s", targetAddr);
                result.context = getMemoryContext(program, addr);
                results.add(result);
            }
        } catch (Exception e) {
            // Ignore individual search errors
        }
    }

    private String getFunctionContext(Program program, Address addr) {
        var func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            long offset = addr.subtract(func.getEntryPoint());
            return String.format("In function %s+0x%x", func.getName(), offset);
        }
        return null;
    }

    private String getMemoryContext(Program program, Address addr) {
        StringBuilder context = new StringBuilder();

        // Check if in function
        var func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            context.append("In function: ").append(func.getName());
        }

        // Check for nearby symbols
        var symbol = program.getSymbolTable().getPrimarySymbol(addr);
        if (symbol != null) {
            if (context.length() > 0) context.append(", ");
            context.append("Symbol: ").append(symbol.getName());
        }

        return context.length() > 0 ? context.toString() : null;
    }

    private static class SearchResult {
        String fromAddress;
        String targetAddress;
        String type;
        String referenceType;
        String description;
        String context;
    }
}