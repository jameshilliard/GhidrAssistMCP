/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for searching instruction patterns.
 */
public class SearchInstructionsTool implements McpTool {

    @Override
    public String getName() {
        return "search_instructions";
    }

    @Override
    public String getDescription() {
        return "Search for instruction patterns by mnemonic or operand patterns";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "mnemonic", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "operand_pattern", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "start_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "end_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "case_sensitive", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of(), null, null, null);
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

        String mnemonic = (String) arguments.get("mnemonic");
        String operandPattern = (String) arguments.get("operand_pattern");
        String startAddrStr = (String) arguments.get("start_address");
        String endAddrStr = (String) arguments.get("end_address");
        Boolean caseSensitive = (Boolean) arguments.get("case_sensitive");
        Integer limit = (Integer) arguments.get("limit");

        if ((mnemonic == null || mnemonic.isEmpty()) &&
            (operandPattern == null || operandPattern.isEmpty())) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either mnemonic or operand_pattern parameter is required")
                .build();
        }

        // Setup search parameters
        Address startAddr = startAddrStr != null ?
            currentProgram.getAddressFactory().getAddress(startAddrStr) :
            currentProgram.getMinAddress();
        Address endAddr = endAddrStr != null ?
            currentProgram.getAddressFactory().getAddress(endAddrStr) :
            currentProgram.getMaxAddress();
        int maxResults = limit != null ? limit : 100;
        boolean isCaseSensitive = caseSensitive != null ? caseSensitive : false;

        if (startAddr == null || endAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format")
                .build();
        }

        // Perform search
        List<SearchResult> results = searchInstructions(currentProgram, mnemonic, operandPattern,
                                                        startAddr, endAddr, isCaseSensitive, maxResults);

        // Format results
        StringBuilder output = new StringBuilder();
        if (mnemonic != null && !mnemonic.isEmpty()) {
            output.append(String.format("Searching for instructions with mnemonic: %s\n", mnemonic));
        }
        if (operandPattern != null && !operandPattern.isEmpty()) {
            output.append(String.format("Operand pattern: %s\n", operandPattern));
        }
        output.append(String.format("Search range: %s - %s\n", startAddr, endAddr));
        output.append(String.format("\nFound %d matches:\n\n", results.size()));

        for (SearchResult result : results) {
            output.append(String.format("@ %s: %s\n", result.address, result.instruction));
            if (result.context != null) {
                output.append(String.format("  %s\n", result.context));
            }
            if (result.flowInfo != null) {
                output.append(String.format("  %s\n", result.flowInfo));
            }
        }

        if (results.size() == maxResults) {
            output.append(String.format("\nShowing first %d matches (limit reached)", maxResults));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }

    private List<SearchResult> searchInstructions(Program program, String mnemonic, String operandPattern,
                                                  Address startAddr, Address endAddr,
                                                  boolean caseSensitive, int maxResults) {
        List<SearchResult> results = new ArrayList<>();
        Listing listing = program.getListing();
        var instrIter = listing.getInstructions(startAddr, true);

        String searchMnemonic = mnemonic;
        String searchPattern = operandPattern;

        if (!caseSensitive) {
            if (searchMnemonic != null) {
                searchMnemonic = searchMnemonic.toLowerCase();
            }
            if (searchPattern != null) {
                searchPattern = searchPattern.toLowerCase();
            }
        }

        while (instrIter.hasNext() && results.size() < maxResults) {
            Instruction instr = instrIter.next();
            Address addr = instr.getAddress();

            if (addr.compareTo(endAddr) > 0) {
                break;
            }

            boolean matches = false;

            // Check mnemonic
            if (searchMnemonic != null) {
                String instrMnemonic = instr.getMnemonicString();
                if (!caseSensitive) {
                    instrMnemonic = instrMnemonic.toLowerCase();
                }
                matches = instrMnemonic.equals(searchMnemonic) ||
                         instrMnemonic.contains(searchMnemonic);
            } else {
                matches = true;
            }

            // Check operand pattern if specified
            if (matches && searchPattern != null) {
                String operandStr = getOperandString(instr);
                if (!caseSensitive) {
                    operandStr = operandStr.toLowerCase();
                }
                matches = operandStr.contains(searchPattern);
            }

            if (matches) {
                SearchResult result = new SearchResult();
                result.address = addr.toString();
                result.instruction = instr.toString();
                result.context = getFunctionContext(program, addr);
                result.flowInfo = getFlowInfo(instr);
                results.add(result);
            }
        }

        return results;
    }

    private String getOperandString(Instruction instr) {
        StringBuilder sb = new StringBuilder();
        int numOperands = instr.getNumOperands();
        for (int i = 0; i < numOperands; i++) {
            if (i > 0) sb.append(", ");
            sb.append(instr.getDefaultOperandRepresentation(i));
        }
        return sb.toString();
    }

    private String getFunctionContext(Program program, Address addr) {
        var func = program.getFunctionManager().getFunctionContaining(addr);
        if (func != null) {
            long offset = addr.subtract(func.getEntryPoint());
            return String.format("In function %s+0x%x", func.getName(), offset);
        }
        return null;
    }

    private String getFlowInfo(Instruction instr) {
        var flowType = instr.getFlowType();
        if (flowType.isCall() || flowType.isJump()) {
            Address[] flows = instr.getFlows();
            if (flows != null && flows.length > 0) {
                return String.format("Flow: %s -> %s", flowType.getName(), flows[0]);
            }
            return String.format("Flow: %s", flowType.getName());
        }
        return null;
    }

    private static class SearchResult {
        String address;
        String instruction;
        String context;
        String flowInfo;
    }
}
