/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for deleting labels/symbols.
 */
public class DeleteLabelTool implements McpTool {

    @Override
    public String getName() {
        return "delete_label";
    }

    @Override
    public String getDescription() {
        return "Delete a label/symbol at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null)
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
        String name = (String) arguments.get("name");

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

        SymbolTable symTable = currentProgram.getSymbolTable();

        int transactionID = currentProgram.startTransaction("Delete label");
        boolean success = false;

        try {
            Symbol[] symbols = symTable.getSymbols(addr);

            if (symbols.length == 0) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No labels found at " + addr)
                    .build();
            }

            int count = 0;
            StringBuilder output = new StringBuilder();

            for (Symbol symbol : symbols) {
                if (!symbol.getSymbolType().toString().equals("Function")) {
                    if (name == null || name.isEmpty() || symbol.getName().equals(name)) {
                        output.append(String.format("Deleted label: %s\n", symbol.getName()));
                        symbol.delete();
                        count++;
                    }
                }
            }

            if (count == 0) {
                if (name != null && !name.isEmpty()) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent(String.format("Label '%s' not found at %s", name, addr))
                        .build();
                } else {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent(String.format("No non-function labels found at %s", addr))
                        .build();
                }
            }

            success = true;

            output.insert(0, String.format("Successfully deleted %d label(s) at %s\n", count, addr));

            return McpSchema.CallToolResult.builder()
                .addTextContent(output.toString())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to delete label: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
