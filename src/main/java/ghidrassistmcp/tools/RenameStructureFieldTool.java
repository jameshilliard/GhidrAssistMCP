/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for renaming structure fields.
 */
public class RenameStructureFieldTool implements McpTool {

    @Override
    public String getName() {
        return "rename_structure_field";
    }

    @Override
    public String getDescription() {
        return "Rename a field in a structure";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "old_field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "new_field_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("structure_name", "old_field_name", "new_field_name"), null, null, null);
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

        String structureName = (String) arguments.get("structure_name");
        String oldFieldName = (String) arguments.get("old_field_name");
        String newFieldName = (String) arguments.get("new_field_name");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required")
                .build();
        }

        if (oldFieldName == null || oldFieldName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("old_field_name parameter is required")
                .build();
        }

        if (newFieldName == null || newFieldName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("new_field_name parameter is required")
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Structure struct = findStructure(dtm, structureName);

        if (struct == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure not found: " + structureName)
                .build();
        }

        DataTypeComponent component = findComponent(struct, oldFieldName);
        if (component == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Field '%s' not found in structure '%s'",
                    oldFieldName, structureName))
                .build();
        }

        int transactionID = currentProgram.startTransaction("Rename structure field");
        boolean success = false;

        try {
            component.setFieldName(newFieldName);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully renamed field '%s' to '%s' in structure '%s'",
                    oldFieldName, newFieldName, structureName))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to rename field: " + e.getMessage())
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

    private DataTypeComponent findComponent(Structure struct, String fieldName) {
        DataTypeComponent[] components = struct.getComponents();
        for (DataTypeComponent comp : components) {
            if (fieldName.equals(comp.getFieldName())) {
                return comp;
            }
        }
        return null;
    }
}
