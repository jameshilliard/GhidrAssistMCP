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
 * MCP tool for deleting fields from structures.
 */
public class DeleteStructureFieldTool implements McpTool {

    @Override
    public String getName() {
        return "delete_structure_field";
    }

    @Override
    public String getDescription() {
        return "Delete a field from a structure";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("structure_name"), null, null, null);
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
        String fieldName = (String) arguments.get("field_name");
        Integer offset = (Integer) arguments.get("offset");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required")
                .build();
        }

        if (fieldName == null && offset == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either field_name or offset parameter is required")
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Structure struct = findStructure(dtm, structureName);

        if (struct == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure not found: " + structureName)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Delete structure field");
        boolean success = false;

        try {
            DataTypeComponent component = null;

            if (offset != null) {
                component = struct.getComponentAt(offset);
            } else {
                component = findComponent(struct, fieldName);
            }

            if (component == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent(String.format("Field not found in structure '%s'", structureName))
                    .build();
            }

            int ordinal = component.getOrdinal();
            String deletedFieldName = component.getFieldName();
            int deletedOffset = component.getOffset();

            struct.delete(ordinal);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully deleted field '%s' at offset 0x%x from structure '%s'",
                    deletedFieldName != null ? deletedFieldName : "<unnamed>",
                    deletedOffset, structureName))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to delete field: " + e.getMessage())
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
