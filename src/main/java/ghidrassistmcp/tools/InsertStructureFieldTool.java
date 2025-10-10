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
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for inserting fields into structures at specific offsets.
 */
public class InsertStructureFieldTool implements McpTool {

    @Override
    public String getName() {
        return "insert_structure_field";
    }

    @Override
    public String getDescription() {
        return "Insert a field into a structure at a specific offset";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "field_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "data_type", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "length", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "comment", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("structure_name", "offset", "field_name", "data_type"), null, null, null);
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
        Integer offset = (Integer) arguments.get("offset");
        String fieldName = (String) arguments.get("field_name");
        String dataTypeName = (String) arguments.get("data_type");
        Integer length = (Integer) arguments.get("length");
        String comment = (String) arguments.get("comment");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required")
                .build();
        }

        if (offset == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("offset parameter is required")
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

        DataType dataType = findDataType(dtm, dataTypeName);
        if (dataType == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Data type not found: " + dataTypeName)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Insert structure field");
        boolean success = false;

        try {
            int fieldLength = length != null ? length : dataType.getLength();
            var component = struct.insertAtOffset(offset, dataType, fieldLength, fieldName, comment);

            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully inserted field '%s' into structure '%s'\nType: %s\nOffset: 0x%x\nSize: %d bytes",
                    fieldName, structureName, dataType.getName(), component.getOffset(), fieldLength))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to insert field: " + e.getMessage())
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
