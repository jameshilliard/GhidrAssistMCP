/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for renaming an existing equate.
 */
public class RenameEquateTool implements McpTool {

    @Override
    public String getName() {
        return "rename_equate";
    }

    @Override
    public String getDescription() {
        return "Rename an existing equate";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "old_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("old_name", "new_name"), null, null, null);
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

        String oldName = (String) arguments.get("old_name");
        String newName = (String) arguments.get("new_name");

        if (oldName == null || oldName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("old_name parameter is required")
                .build();
        }

        if (newName == null || newName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("new_name parameter is required")
                .build();
        }

        EquateTable equateTable = currentProgram.getEquateTable();
        Equate equate = equateTable.getEquate(oldName);

        if (equate == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Equate not found: " + oldName)
                .build();
        }

        Equate existingNew = equateTable.getEquate(newName);
        if (existingNew != null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Equate '%s' already exists with value 0x%X",
                    newName, existingNew.getValue()))
                .build();
        }

        int transactionID = currentProgram.startTransaction("Rename equate");
        boolean success = false;

        try {
            equate.renameEquate(newName);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully renamed equate '%s' to '%s' (value: 0x%X, %d references)",
                    oldName, newName, equate.getValue(), equate.getReferenceCount()))
                .build();

        } catch (DuplicateNameException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Equate name already exists: " + newName)
                .build();
        } catch (InvalidInputException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid equate name: " + e.getMessage())
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to rename equate: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
