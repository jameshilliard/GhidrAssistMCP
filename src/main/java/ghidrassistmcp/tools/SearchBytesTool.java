/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for searching byte patterns in program memory.
 */
public class SearchBytesTool implements McpTool {

    @Override
    public String getName() {
        return "search_bytes";
    }

    @Override
    public String getDescription() {
        return "Search for byte patterns in program memory (hex string format)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "pattern", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "start_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "end_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "alignment", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("pattern"), null, null, null);
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

        String pattern = (String) arguments.get("pattern");
        String startAddrStr = (String) arguments.get("start_address");
        String endAddrStr = (String) arguments.get("end_address");
        Integer limit = (Integer) arguments.get("limit");
        Integer alignment = (Integer) arguments.get("alignment");

        if (pattern == null || pattern.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Pattern parameter is required")
                .build();
        }

        // Parse hex pattern
        byte[] searchBytes = parseHexPattern(pattern);
        if (searchBytes == null || searchBytes.length == 0) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid hex pattern format. Use format like '48 65 6C 6C 6F' or '48656C6C6F'")
                .build();
        }

        // Setup search parameters
        Memory memory = currentProgram.getMemory();
        Address startAddr = startAddrStr != null ?
            currentProgram.getAddressFactory().getAddress(startAddrStr) :
            currentProgram.getMinAddress();
        Address endAddr = endAddrStr != null ?
            currentProgram.getAddressFactory().getAddress(endAddrStr) :
            currentProgram.getMaxAddress();
        int maxResults = limit != null ? limit : 100;
        int searchAlignment = alignment != null ? alignment : 1;

        if (startAddr == null || endAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format")
                .build();
        }

        // Perform search
        List<SearchResult> results = searchForBytes(memory, searchBytes, startAddr, endAddr, maxResults, searchAlignment);

        // Format results
        StringBuilder output = new StringBuilder();
        output.append(String.format("Searching for byte pattern: %s\n", formatHexBytes(searchBytes)));
        output.append(String.format("Search range: %s - %s\n", startAddr, endAddr));
        if (searchAlignment > 1) {
            output.append(String.format("Alignment: %d bytes\n", searchAlignment));
        }
        output.append(String.format("\nFound %d matches:\n\n", results.size()));

        for (SearchResult result : results) {
            output.append(String.format("@ %s: %s", result.address, result.context));
            if (result.description != null) {
                output.append(String.format(" (%s)", result.description));
            }
            output.append("\n");
        }

        if (results.size() == maxResults) {
            output.append(String.format("\nShowing first %d matches (limit reached)", maxResults));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }

    private byte[] parseHexPattern(String pattern) {
        try {
            // Remove spaces, commas, 0x prefixes
            String cleaned = pattern.replaceAll("[\\s,]", "")
                                  .replaceAll("0x", "")
                                  .replaceAll("0X", "");

            // Validate hex string
            if (!cleaned.matches("[0-9A-Fa-f]*") || cleaned.length() % 2 != 0) {
                return null;
            }

            // Convert to byte array
            byte[] bytes = new byte[cleaned.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
            }

            return bytes;
        } catch (Exception e) {
            Msg.error(this, "Failed to parse hex pattern: " + pattern, e);
            return null;
        }
    }

    private String formatHexBytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length && i < 16; i++) {
            if (i > 0) sb.append(" ");
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        if (bytes.length > 16) {
            sb.append(" ... (").append(bytes.length).append(" bytes total)");
        }
        return sb.toString();
    }

    private List<SearchResult> searchForBytes(Memory memory, byte[] pattern, Address startAddr,
                                             Address endAddr, int maxResults, int alignment) {
        List<SearchResult> results = new ArrayList<>();

        try {
            // Create address set for search range
            AddressSet searchSet = new AddressSet(startAddr, endAddr);
            AddressRangeIterator rangeIter = searchSet.getAddressRanges();

            while (rangeIter.hasNext() && results.size() < maxResults) {
                AddressRange range = rangeIter.next();
                Address currentAddr = range.getMinAddress();

                // Search within this range
                while (currentAddr != null && currentAddr.compareTo(range.getMaxAddress()) <= 0 && results.size() < maxResults) {
                    // Check alignment
                    if (currentAddr.getOffset() % alignment == 0) {
                        // Try to match pattern at this address
                        if (matchesPattern(memory, currentAddr, pattern)) {
                            SearchResult result = new SearchResult();
                            result.address = currentAddr.toString();
                            result.context = getByteContext(memory, currentAddr, pattern.length);
                            result.description = getAddressDescription(memory.getProgram(), currentAddr);
                            results.add(result);
                        }
                    }

                    // Move to next address (respecting alignment)
                    try {
                        if (alignment > 1) {
                            currentAddr = currentAddr.add(alignment);
                        } else {
                            currentAddr = currentAddr.add(1);
                        }

                        // Check if we've gone past the range
                        if (currentAddr.compareTo(range.getMaxAddress()) > 0) {
                            break;
                        }
                    } catch (Exception e) {
                        break; // Address overflow
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error during byte search", e);
        }

        return results;
    }

    private boolean matchesPattern(Memory memory, Address addr, byte[] pattern) {
        try {
            byte[] bytes = new byte[pattern.length];
            if (memory.getBytes(addr, bytes) == pattern.length) {
                for (int i = 0; i < pattern.length; i++) {
                    if (bytes[i] != pattern[i]) {
                        return false;
                    }
                }
                return true;
            }
        } catch (MemoryAccessException e) {
            // Memory not accessible at this address
        }
        return false;
    }

    private String getByteContext(Memory memory, Address addr, int patternLength) {
        try {
            // Show pattern bytes plus some context
            int contextBefore = 4;
            int contextAfter = 4;
            int totalBytes = contextBefore + patternLength + contextAfter;

            Address startAddr = addr.subtract(contextBefore);
            byte[] bytes = new byte[totalBytes];
            memory.getBytes(startAddr, bytes);

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                if (i == contextBefore) sb.append("[");
                if (i == contextBefore + patternLength) sb.append("]");
                if (i > 0) sb.append(" ");
                sb.append(String.format("%02X", bytes[i] & 0xFF));
            }

            return sb.toString();
        } catch (Exception e) {
            // Fallback to just showing the pattern bytes
            try {
                byte[] bytes = new byte[Math.min(patternLength, 16)];
                memory.getBytes(addr, bytes);
                return formatHexBytes(bytes);
            } catch (Exception e2) {
                return "??";
            }
        }
    }

    private String getAddressDescription(Program program, Address addr) {
        // Check if address is in a function
        var func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            long offset = addr.subtract(func.getEntryPoint());
            return String.format("%s+0x%x", func.getName(), offset);
        }

        // Check if address has a label
        var symbol = program.getSymbolTable().getPrimarySymbol(addr);
        if (symbol != null) {
            return symbol.getName();
        }

        // Check if address is in defined data
        var data = program.getListing().getDefinedDataAt(addr);
        if (data != null && data.hasStringValue()) {
            return "string: \"" + data.getValue() + "\"";
        }

        return null;
    }

    private static class SearchResult {
        String address;
        String context;
        String description;
    }
}