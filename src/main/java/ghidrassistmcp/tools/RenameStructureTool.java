/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.DuplicateNameException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for renaming structure types.
 */
public class RenameStructureTool implements McpTool {

    @Override
    public String getName() {
        return "rename_structure";
    }

    @Override
    public String getDescription() {
        return "Rename a structure type";
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

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Structure struct = findStructure(dtm, oldName);

        if (struct == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure not found: " + oldName)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Rename structure");
        boolean success = false;

        try {
            struct.setName(newName);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully renamed structure '%s' to '%s'",
                    oldName, newName))
                .build();

        } catch (DuplicateNameException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure name already exists: " + newName)
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to rename structure: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }

    private Structure findStructure(DataTypeManager dtm, String name) {
        DataType dt = dtm.getDataType(name);
        if (dt instanceof Structure) {
            return (Structure) dt;
        }

        var iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate instanceof Structure && candidate.getName().equals(name)) {
                return (Structure) candidate;
            }
        }

        return null;
    }
}
