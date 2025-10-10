/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for removing data definitions (making undefined).
 */
public class UndefineDataTool implements McpTool {

    @Override
    public String getName() {
        return "undefine_data";
    }

    @Override
    public String getDescription() {
        return "Remove data definition at an address (make undefined)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address"), null, null, null);
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

        String addrStr = (String) arguments.get("address");

        if (addrStr == null || addrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

        Listing listing = currentProgram.getListing();
        Data data = listing.getDefinedDataAt(addr);

        if (data == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No defined data at " + addr)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Undefine data");
        boolean success = false;

        try {
            String dataTypeName = data.getDataType().getName();
            int length = data.getLength();

            listing.clearCodeUnits(addr, addr.add(length - 1), false);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully undefined data at %s\nPrevious type: %s\nSize: %d bytes",
                    addr, dataTypeName, length))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to undefine data: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
