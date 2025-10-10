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
 * MCP tool for setting the data type of a structure field.
 */
public class SetStructureFieldTypeTool implements McpTool {

    @Override
    public String getName() {
        return "set_structure_field_type";
    }

    @Override
    public String getDescription() {
        return "Set the data type of a structure field";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "data_type", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("structure_name", "field_name", "data_type"), null, null, null);
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
        String dataTypeName = (String) arguments.get("data_type");

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

        if (dataTypeName == null || dataTypeName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("data_type parameter is required")
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

        DataType newDataType = findDataType(dtm, dataTypeName);
        if (newDataType == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Data type not found: " + dataTypeName +
                    "\nTry using full path like '/uint' or 'pointer'")
                .build();
        }

        int transactionID = currentProgram.startTransaction("Set structure field type");
        boolean success = false;

        try {
            DataType oldType = component.getDataType();
            struct.replace(component.getOrdinal(), newDataType, newDataType.getLength());

            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully changed field '%s' type from '%s' to '%s' in structure '%s'",
                    fieldName, oldType.getName(), newDataType.getName(), structureName))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to set field type: " + e.getMessage())
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

    private DataType findDataType(DataTypeManager dtm, String name) {
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }

        String[] searchNames = {
            name,
            "/" + name,
            name.toLowerCase(),
            "/" + name.toLowerCase()
        };

        for (String searchName : searchNames) {
            dt = dtm.getDataType(searchName);
            if (dt != null) {
                return dt;
            }
        }

        var iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equalsIgnoreCase(name)) {
                return candidate;
            }
        }

        return null;
    }
}
