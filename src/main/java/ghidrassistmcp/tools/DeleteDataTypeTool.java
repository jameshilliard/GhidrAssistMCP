/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for deleting data types (structures, typedefs, etc.).
 */
public class DeleteDataTypeTool implements McpTool {

    @Override
    public String getName() {
        return "delete_datatype";
    }

    @Override
    public String getDescription() {
        return "Delete a data type (structure, typedef, etc.)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "datatype_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("datatype_name"), null, null, null);
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

        String datatypeName = (String) arguments.get("datatype_name");

        if (datatypeName == null || datatypeName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("datatype_name parameter is required")
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType dataType = findDataType(dtm, datatypeName);

        if (dataType == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Data type not found: " + datatypeName)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Delete data type");
        boolean success = false;

        try {
            boolean removed = dtm.remove(dataType, null);
            success = removed;

            if (removed) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent(String.format("Successfully deleted data type '%s'", datatypeName))
                    .build();
            } else {
                return McpSchema.CallToolResult.builder()
                    .addTextContent(String.format("Failed to delete data type '%s' (may be in use)", datatypeName))
                    .build();
            }

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to delete data type: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }

    private DataType findDataType(DataTypeManager dtm, String name) {
        // Try direct lookup first
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }

        // Search all data types
        var iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equals(name)) {
                return candidate;
            }
        }

        return null;
    }
}
