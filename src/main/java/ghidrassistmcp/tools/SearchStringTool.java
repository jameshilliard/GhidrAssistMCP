/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for searching specific strings in program memory.
 * Unlike ListStringsTool which lists all strings, this searches for specific string patterns.
 */
public class SearchStringTool implements McpTool {

    @Override
    public String getName() {
        return "search_string";
    }

    @Override
    public String getDescription() {
        return "Search for specific strings or string patterns in program memory";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "pattern", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "case_sensitive", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "exact_match", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "include_unicode", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "min_length", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
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
        Boolean caseSensitive = (Boolean) arguments.get("case_sensitive");
        Boolean exactMatch = (Boolean) arguments.get("exact_match");
        Boolean includeUnicode = (Boolean) arguments.get("include_unicode");
        Integer minLength = (Integer) arguments.get("min_length");
        Integer limit = (Integer) arguments.get("limit");

        if (pattern == null || pattern.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Pattern parameter is required")
                .build();
        }

        // Setup search parameters
        boolean isCaseSensitive = caseSensitive != null ? caseSensitive : false;
        boolean isExactMatch = exactMatch != null ? exactMatch : false;
        boolean searchUnicode = includeUnicode != null ? includeUnicode : false;
        int minLen = minLength != null ? minLength : 4;
        int maxResults = limit != null ? limit : 100;

        // Perform search
        List<SearchResult> results = searchForString(currentProgram, pattern, isCaseSensitive,
                                                     isExactMatch, searchUnicode, minLen, maxResults);

        // Format results
        StringBuilder output = new StringBuilder();
        output.append(String.format("Searching for string: \"%s\"\n", pattern));
        output.append(String.format("Options: %s, %s\n",
            isCaseSensitive ? "case-sensitive" : "case-insensitive",
            isExactMatch ? "exact match" : "wildcard match"));
        if (searchUnicode) {
            output.append("Including Unicode strings\n");
        }
        output.append(String.format("\nFound %d matches:\n\n", results.size()));

        for (SearchResult result : results) {
            output.append(String.format("@ %s: \"%s\"", result.address, result.string));
            if (result.type != null) {
                output.append(String.format(" [%s]", result.type));
            }
            output.append("\n");

            if (result.length != result.string.length()) {
                output.append(String.format("  Full length: %d bytes\n", result.length));
            }
            if (result.references != null && !result.references.isEmpty()) {
                output.append(String.format("  Referenced by: %s\n", result.references));
            }
            if (result.context != null) {
                output.append(String.format("  Context: %s\n", result.context));
            }
        }

        if (results.size() == maxResults) {
            output.append(String.format("\nShowing first %d matches (limit reached)", maxResults));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }

    private List<SearchResult> searchForString(Program program, String pattern, boolean caseSensitive,
                                              boolean exactMatch, boolean includeUnicode,
                                              int minLength, int maxResults) {
        List<SearchResult> results = new ArrayList<>();

        // First search in defined string data
        searchDefinedStrings(program, pattern, caseSensitive, exactMatch, results, maxResults);

        // Then search raw memory for ASCII strings
        if (results.size() < maxResults) {
            searchMemoryStrings(program, pattern, caseSensitive, exactMatch, false, minLength, results, maxResults);
        }

        // Search for Unicode strings if requested
        if (includeUnicode && results.size() < maxResults) {
            searchMemoryStrings(program, pattern, caseSensitive, exactMatch, true, minLength, results, maxResults);
        }

        return results;
    }

    private void searchDefinedStrings(Program program, String pattern, boolean caseSensitive,
                                     boolean exactMatch, List<SearchResult> results, int maxResults) {
        Listing listing = program.getListing();
        var dataIter = listing.getDefinedData(true);

        while (dataIter.hasNext() && results.size() < maxResults) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                Object value = data.getValue();
                if (value instanceof String) {
                    String str = (String) value;
                    if (matchesPattern(str, pattern, caseSensitive, exactMatch)) {
                        SearchResult result = new SearchResult();
                        result.address = data.getAddress().toString();
                        result.string = str;
                        result.length = data.getLength();
                        result.type = data.getDataType().getName();
                        result.references = getReferences(program, data.getAddress());
                        result.context = getStringContext(program, data.getAddress());
                        results.add(result);
                    }
                }
            }
        }
    }

    private void searchMemoryStrings(Program program, String pattern, boolean caseSensitive,
                                    boolean exactMatch, boolean unicode, int minLength,
                                    List<SearchResult> results, int maxResults) {
        Memory memory = program.getMemory();
        Address addr = memory.getMinAddress();

        while (addr != null && results.size() < maxResults) {
            try {
                // Look for string-like sequences
                String str = unicode ? findUnicodeString(memory, addr, minLength) :
                                     findAsciiString(memory, addr, minLength);

                if (str != null && matchesPattern(str, pattern, caseSensitive, exactMatch)) {
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
                        result.string = str.length() > 100 ? str.substring(0, 100) + "..." : str;
                        result.length = str.length() * (unicode ? 2 : 1);
                        result.type = unicode ? "Unicode" : "ASCII";
                        result.references = getReferences(program, addr);
                        result.context = getStringContext(program, addr);
                        results.add(result);
                    }

                    // Skip past this string
                    addr = addr.add(str.length() * (unicode ? 2 : 1));
                } else {
                    addr = addr.add(1);
                }

                // Check if we've reached the end of memory
                if (addr.compareTo(memory.getMaxAddress()) > 0) {
                    break;
                }
            } catch (Exception e) {
                // Move to next address
                try {
                    addr = addr.add(1);
                } catch (Exception e2) {
                    break;
                }
            }
        }
    }

    private String findAsciiString(Memory memory, Address addr, int minLength) {
        try {
            StringBuilder sb = new StringBuilder();
            Address current = addr;

            while (true) {
                byte b = memory.getByte(current);
                if (b == 0) {
                    // Null terminator found
                    if (sb.length() >= minLength) {
                        return sb.toString();
                    } else {
                        return null;
                    }
                } else if (isPrintableAscii(b)) {
                    sb.append((char) b);
                    if (sb.length() > 1000) {
                        // Reasonable limit
                        return sb.toString();
                    }
                } else {
                    // Non-printable character
                    return sb.length() >= minLength ? sb.toString() : null;
                }
                current = current.add(1);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private String findUnicodeString(Memory memory, Address addr, int minLength) {
        try {
            StringBuilder sb = new StringBuilder();
            Address current = addr;
            boolean littleEndian = !memory.getProgram().getLanguage().isBigEndian();

            while (true) {
                byte b1 = memory.getByte(current);
                byte b2 = memory.getByte(current.add(1));

                char ch = littleEndian ? (char) ((b2 << 8) | (b1 & 0xFF)) :
                                        (char) ((b1 << 8) | (b2 & 0xFF));

                if (ch == 0) {
                    // Null terminator
                    if (sb.length() >= minLength) {
                        return sb.toString();
                    } else {
                        return null;
                    }
                } else if (isPrintableUnicode(ch)) {
                    sb.append(ch);
                    if (sb.length() > 500) {
                        // Reasonable limit for Unicode
                        return sb.toString();
                    }
                } else {
                    // Non-printable character
                    return sb.length() >= minLength ? sb.toString() : null;
                }
                current = current.add(2);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isPrintableAscii(byte b) {
        return b >= 0x20 && b < 0x7F;
    }

    private boolean isPrintableUnicode(char ch) {
        // Basic printable range
        return (ch >= 0x20 && ch < 0x7F) ||
               (ch >= 0xA0 && ch <= 0xD7FF) ||
               (ch >= 0xE000 && ch <= 0xFFFD);
    }

    private boolean matchesPattern(String str, String pattern, boolean caseSensitive, boolean exactMatch) {
        if (!caseSensitive) {
            str = str.toLowerCase();
            pattern = pattern.toLowerCase();
        }

        if (exactMatch) {
            return str.equals(pattern);
        }

        // Convert wildcard pattern to regex
        String regex = pattern.replace(".", "\\.")
                             .replace("?", ".")
                             .replace("*", ".*");

        try {
            return str.matches(regex);
        } catch (Exception e) {
            // Fall back to contains for simple patterns
            return str.contains(pattern.replace("*", "").replace("?", ""));
        }
    }

    private String getReferences(Program program, Address addr) {
        List<String> refs = new ArrayList<>();
        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);

        int count = 0;
        while (refIter.hasNext() && count < 3) {
            Reference ref = refIter.next();
            Address fromAddr = ref.getFromAddress();
            var func = program.getFunctionManager().getFunctionContaining(fromAddr);
            if (func != null) {
                refs.add(func.getName());
            } else {
                refs.add(fromAddr.toString());
            }
            count++;
        }

        if (refs.isEmpty()) {
            return null;
        }
        return String.join(", ", refs) + (refIter.hasNext() ? ", ..." : "");
    }

    private String getStringContext(Program program, Address addr) {
        // Check if in a function
        var func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            return "In function: " + func.getName();
        }

        // Check for section/segment
        var block = program.getMemory().getBlock(addr);
        if (block != null) {
            return "In section: " + block.getName();
        }

        return null;
    }

    private static class SearchResult {
        String address;
        String string;
        int length;
        String type;
        String references;
        String context;
    }
}