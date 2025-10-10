/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for deleting an equate definition entirely.
 */
public class DeleteEquateTool implements McpTool {

    @Override
    public String getName() {
        return "delete_equate";
    }

    @Override
    public String getDescription() {
        return "Delete an equate definition and all its references";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("name"), null, null, null);
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

        String name = (String) arguments.get("name");

        if (name == null || name.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("name parameter is required")
                .build();
        }

        EquateTable equateTable = currentProgram.getEquateTable();
        Equate equate = equateTable.getEquate(name);

        if (equate == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Equate not found: " + name)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Delete equate");
        boolean success = false;

        try {
            int refCount = equate.getReferenceCount();
            long value = equate.getValue();

            equateTable.removeEquate(name);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully deleted equate '%s' (value: 0x%X, %d references removed)",
                    name, value, refCount))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to delete equate: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
