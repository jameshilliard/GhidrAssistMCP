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
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for searching scalar values in code and data.
 */
public class SearchScalarsTool implements McpTool {

    @Override
    public String getName() {
        return "search_scalars";
    }

    @Override
    public String getDescription() {
        return "Search for scalar values (constants, magic numbers, addresses) in code and data";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "value", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "size", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "include_instructions", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "include_data", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "endian", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("value"), null, null, null);
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

        String valueStr = (String) arguments.get("value");
        Integer size = (Integer) arguments.get("size");
        Integer limit = (Integer) arguments.get("limit");
        Boolean includeInstructions = (Boolean) arguments.get("include_instructions");
        Boolean includeData = (Boolean) arguments.get("include_data");
        String endianStr = (String) arguments.get("endian");

        if (valueStr == null || valueStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Value parameter is required")
                .build();
        }

        // Parse value
        long searchValue;
        try {
            if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                searchValue = Long.parseUnsignedLong(valueStr.substring(2), 16);
            } else {
                searchValue = Long.parseLong(valueStr);
            }
        } catch (NumberFormatException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid value format. Use decimal or hex with 0x prefix")
                .build();
        }

        // Setup search parameters
        int maxResults = limit != null ? limit : 100;
        boolean searchInstructions = includeInstructions != null ? includeInstructions : true;
        boolean searchData = includeData != null ? includeData : true;

        // Perform search
        List<SearchResult> results = searchForScalar(currentProgram, searchValue, size,
                                                     searchInstructions, searchData, maxResults, endianStr);

        // Format results
        StringBuilder output = new StringBuilder();
        output.append(String.format("Searching for scalar value: 0x%X (%d)\n", searchValue, searchValue));
        if (size != null) {
            output.append(String.format("Size constraint: %d bytes\n", size));
        }
        output.append(String.format("Search scope: %s%s\n",
            searchInstructions ? "instructions" : "",
            searchData ? (searchInstructions ? " and data" : "data") : ""));
        output.append(String.format("\nFound %d matches:\n\n", results.size()));

        for (SearchResult result : results) {
            output.append(String.format("@ %s: %s\n", result.address, result.description));
            if (result.context != null) {
                output.append(String.format("  Context: %s\n", result.context));
            }
            if (result.references != null && !result.references.isEmpty()) {
                output.append(String.format("  References: %s\n", result.references));
            }
        }

        if (results.size() == maxResults) {
            output.append(String.format("\nShowing first %d matches (limit reached)", maxResults));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }

    private List<SearchResult> searchForScalar(Program program, long value, Integer sizeConstraint,
                                              boolean searchInstructions, boolean searchData,
                                              int maxResults, String endianStr) {
        List<SearchResult> results = new ArrayList<>();
        Listing listing = program.getListing();

        // Search in instructions
        if (searchInstructions) {
            searchInstructionOperands(program, listing, value, sizeConstraint, results, maxResults);
        }

        // Search in defined data
        if (searchData && results.size() < maxResults) {
            searchDefinedData(program, listing, value, sizeConstraint, results, maxResults);
        }

        // Also search raw memory for the value (important for SRAM dumps)
        if (results.size() < maxResults) {
            searchRawMemory(program, value, sizeConstraint, endianStr, results, maxResults);
        }

        return results;
    }

    private void searchInstructionOperands(Program program, Listing listing, long value,
                                          Integer sizeConstraint, List<SearchResult> results, int maxResults) {
        var instrIter = listing.getInstructions(true);

        while (instrIter.hasNext() && results.size() < maxResults) {
            Instruction instr = instrIter.next();
            Address addr = instr.getAddress();
            if (instr == null) continue;

            // Check each operand
            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                Object[] opObjs = instr.getOpObjects(i);
                for (Object obj : opObjs) {
                    if (obj instanceof Scalar) {
                        Scalar scalar = (Scalar) obj;
                        if (scalar.getUnsignedValue() == value || scalar.getSignedValue() == value) {
                            // Check size constraint if provided
                            if (sizeConstraint == null) {
                                SearchResult result = new SearchResult();
                                result.address = addr.toString();
                                result.type = "Instruction";
                                result.description = String.format("%s (operand %d: 0x%X)",
                                    instr.toString(), i, scalar.getUnsignedValue());
                                result.context = getInstructionContext(program, instr);
                                results.add(result);
                                break;
                            }
                        }
                    } else if (obj instanceof Address) {
                        Address refAddr = (Address) obj;
                        if (refAddr.getOffset() == value) {
                            SearchResult result = new SearchResult();
                            result.address = addr.toString();
                            result.type = "Instruction";
                            result.description = String.format("%s (address operand: %s)",
                                instr.toString(), refAddr.toString());
                            result.context = getInstructionContext(program, instr);
                            results.add(result);
                            break;
                        }
                    }
                }
            }
        }
    }

    private void searchDefinedData(Program program, Listing listing, long value,
                                  Integer sizeConstraint, List<SearchResult> results, int maxResults) {
        var dataIter = listing.getDefinedData(true);

        while (dataIter.hasNext() && results.size() < maxResults) {
            Data data = dataIter.next();
            Address addr = data.getAddress();
            if (data == null) continue;

            // Check if data value matches
            if (data.isPointer()) {
                Address ptrAddr = (Address) data.getValue();
                if (ptrAddr != null && ptrAddr.getOffset() == value) {
                    SearchResult result = new SearchResult();
                    result.address = addr.toString();
                    result.type = "Pointer";
                    result.description = String.format("Pointer -> %s", ptrAddr.toString());
                    result.references = getReferencesDescription(program, addr);
                    results.add(result);
                }
            } else if (data.getValue() instanceof Scalar) {
                Scalar scalar = (Scalar) data.getValue();
                if (scalar.getUnsignedValue() == value || scalar.getSignedValue() == value) {
                    if (sizeConstraint == null || data.getLength() == sizeConstraint) {
                        SearchResult result = new SearchResult();
                        result.address = addr.toString();
                        result.type = "Data";
                        result.description = String.format("%s = 0x%X (%d)",
                            data.getDataType().getName(), scalar.getUnsignedValue(), scalar.getSignedValue());
                        result.references = getReferencesDescription(program, addr);
                        results.add(result);
                    }
                }
            } else if (data.getValue() instanceof Long) {
                Long dataValue = (Long) data.getValue();
                if (dataValue == value) {
                    SearchResult result = new SearchResult();
                    result.address = addr.toString();
                    result.type = "Data";
                    result.description = String.format("%s = 0x%X", data.getDataType().getName(), dataValue);
                    results.add(result);
                }
            }
        }
    }

    private void searchRawMemory(Program program, long value, Integer sizeConstraint,
                                String endianStr, List<SearchResult> results, int maxResults) {
        Memory memory = program.getMemory();
        boolean checkLittle = endianStr == null || "little".equals(endianStr) || "both".equals(endianStr);
        boolean checkBig = "big".equals(endianStr) || "both".equals(endianStr);

        // If no endianness specified, use program's default
        if (endianStr == null) {
            checkLittle = !program.getLanguage().isBigEndian();
            checkBig = program.getLanguage().isBigEndian();
        }

        // Determine sizes to check
        List<Integer> sizes = new ArrayList<>();
        if (sizeConstraint != null) {
            sizes.add(sizeConstraint);
        } else {
            // Check common sizes
            if ((value & 0xFFFFFFFF00000000L) == 0) sizes.add(4); // 32-bit value
            if ((value & 0xFFFF0000FFFFFFFFL) == 0) sizes.add(2); // 16-bit value
            if ((value & 0xFF00FFFFFFFFFFFFL) == 0) sizes.add(1); // 8-bit value
            if (sizes.isEmpty()) sizes.add(8); // 64-bit value
        }

        // Search for each size
        for (Integer size : sizes) {
            if (results.size() >= maxResults) break;

            byte[] pattern = createBytePattern(value, size, checkLittle);
            if (pattern != null) {
                searchMemoryForPattern(memory, pattern, "little-endian", size, value, results, maxResults);
            }

            if (checkBig && checkLittle) {
                pattern = createBytePattern(value, size, false);
                if (pattern != null) {
                    searchMemoryForPattern(memory, pattern, "big-endian", size, value, results, maxResults);
                }
            }
        }
    }

    private byte[] createBytePattern(long value, int size, boolean littleEndian) {
        byte[] pattern = new byte[size];

        for (int i = 0; i < size; i++) {
            if (littleEndian) {
                pattern[i] = (byte) ((value >> (i * 8)) & 0xFF);
            } else {
                pattern[size - 1 - i] = (byte) ((value >> (i * 8)) & 0xFF);
            }
        }

        return pattern;
    }

    private void searchMemoryForPattern(Memory memory, byte[] pattern, String endianness,
                                       int size, long value, List<SearchResult> results, int maxResults) {
        try {
            Address addr = memory.findBytes(memory.getMinAddress(), pattern, null, true, null);

            while (addr != null && results.size() < maxResults) {
                // Check if we already have this address
                boolean duplicate = false;
                for (SearchResult existing : results) {
                    if (existing.address.equals(addr.toString())) {
                        duplicate = true;
                        break;
                    }
                }

                if (!duplicate) {
                    SearchResult result = new SearchResult();
                    result.address = addr.toString();
                    result.type = "Memory";
                    result.description = String.format("Raw %d-byte %s value: 0x%X",
                        size, endianness, value);

                    // Add context about location
                    var func = memory.getProgram().getFunctionManager().getFunctionContaining(addr);
                    if (func != null) {
                        result.context = "In function: " + func.getName();
                    }

                    results.add(result);
                }

                // Search for next occurrence
                addr = memory.findBytes(addr.add(1), pattern, null, true, null);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error searching memory for pattern", e);
        }
    }

    private String getInstructionContext(Program program, Instruction instr) {
        var func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
        if (func != null) {
            long offset = instr.getAddress().subtract(func.getEntryPoint());
            return String.format("In %s+0x%x", func.getName(), offset);
        }
        return null;
    }

    private String getReferencesDescription(Program program, Address addr) {
        List<String> refs = new ArrayList<>();
        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);

        int count = 0;
        while (refIter.hasNext() && count < 3) {
            Reference ref = refIter.next();
            var fromFunc = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (fromFunc != null) {
                refs.add(fromFunc.getName());
            } else {
                refs.add(ref.getFromAddress().toString());
            }
            count++;
        }

        if (refs.isEmpty()) return null;
        return String.join(", ", refs) + (refIter.hasNext() ? ", ..." : "");
    }

    private static class SearchResult {
        String address;
        String type;
        String description;
        String context;
        String references;
    }
}