/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for clearing code units in a range.
 */
public class ClearCodeUnitsTool implements McpTool {

    @Override
    public String getName() {
        return "clear_code_units";
    }

    @Override
    public String getDescription() {
        return "Clear existing code/data definitions in an address range";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "start_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "end_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "clear_context", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of("start_address", "end_address"), null, null, null);
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

        String startAddrStr = (String) arguments.get("start_address");
        String endAddrStr = (String) arguments.get("end_address");
        Boolean clearContext = (Boolean) arguments.get("clear_context");

        if (startAddrStr == null || startAddrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("start_address parameter is required")
                .build();
        }

        if (endAddrStr == null || endAddrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("end_address parameter is required")
                .build();
        }

        Address startAddr = currentProgram.getAddressFactory().getAddress(startAddrStr);
        if (startAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid start_address format: " + startAddrStr)
                .build();
        }

        Address endAddr = currentProgram.getAddressFactory().getAddress(endAddrStr);
        if (endAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid end_address format: " + endAddrStr)
                .build();
        }

        boolean shouldClearContext = clearContext != null ? clearContext : false;

        int transactionID = currentProgram.startTransaction("Clear code units");
        boolean success = false;

        try {
            Listing listing = currentProgram.getListing();
            listing.clearCodeUnits(startAddr, endAddr, shouldClearContext);

            success = true;

            long size = endAddr.subtract(startAddr) + 1;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully cleared code units from %s to %s (%d bytes)\nContext cleared: %s",
                    startAddr, endAddr, size, shouldClearContext ? "yes" : "no"))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to clear code units: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
