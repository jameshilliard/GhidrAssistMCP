/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for creating array data types.
 */
public class CreateArrayTypeTool implements McpTool {

    @Override
    public String getName() {
        return "create_array_type";
    }

    @Override
    public String getDescription() {
        return "Create an array data type that can be used in structures";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "base_type", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "element_count", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "type_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("base_type", "element_count"), null, null, null);
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

        String baseTypeName = (String) arguments.get("base_type");
        Object elementCountObj = arguments.get("element_count");
        String typeName = (String) arguments.get("type_name");

        if (baseTypeName == null || baseTypeName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("base_type parameter is required")
                .build();
        }

        if (elementCountObj == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("element_count parameter is required")
                .build();
        }

        int elementCount;
        if (elementCountObj instanceof Integer) {
            elementCount = (Integer) elementCountObj;
        } else if (elementCountObj instanceof Long) {
            elementCount = ((Long) elementCountObj).intValue();
        } else {
            return McpSchema.CallToolResult.builder()
                .addTextContent("element_count must be an integer")
                .build();
        }

        if (elementCount <= 0) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("element_count must be greater than 0")
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType baseType = dtm.getDataType("/" + baseTypeName);

        if (baseType == null) {
            // Try without leading slash
            baseType = dtm.getDataType(baseTypeName);
        }

        if (baseType == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Base type not found: " + baseTypeName)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Create array type");
        boolean success = false;

        try {
            ArrayDataType arrayType = new ArrayDataType(baseType, elementCount, baseType.getLength());

            DataType resolvedType;
            if (typeName != null && !typeName.isEmpty()) {
                // Create with specific name via typedef
                resolvedType = dtm.addDataType(arrayType, null);
            } else {
                resolvedType = dtm.resolve(arrayType, null);
            }

            success = true;

            String resultName = resolvedType.getName();
            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully created array type '%s' (%s[%d], %d bytes total)",
                    resultName, baseTypeName, elementCount, resolvedType.getLength()))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create array type: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
