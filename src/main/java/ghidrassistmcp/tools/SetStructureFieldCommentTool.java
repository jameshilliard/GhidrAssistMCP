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
 * MCP tool for setting comments on structure fields.
 */
public class SetStructureFieldCommentTool implements McpTool {

    @Override
    public String getName() {
        return "set_structure_field_comment";
    }

    @Override
    public String getDescription() {
        return "Set a comment on a structure field";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "comment", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("structure_name", "field_name", "comment"), null, null, null);
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
        String comment = (String) arguments.get("comment");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required")
                .build();
        }

        if (fieldName == null || fieldName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("field_name parameter is required")
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Structure struct = findStructure(dtm, structureName);

        if (struct == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure not found: " + structureName)
                .build();
        }

        DataTypeComponent component = findComponent(struct, fieldName);
        if (component == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Field '%s' not found in structure '%s'",
                    fieldName, structureName))
                .build();
        }

        int transactionID = currentProgram.startTransaction("Set structure field comment");
        boolean success = false;

        try {
            component.setComment(comment);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully set comment on field '%s' in structure '%s'",
                    fieldName, structureName))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to set field comment: " + e.getMessage())
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
