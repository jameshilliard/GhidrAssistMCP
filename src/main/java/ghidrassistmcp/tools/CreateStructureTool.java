/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for creating a new structure definition.
 */
public class CreateStructureTool implements McpTool {

    @Override
    public String getName() {
        return "create_structure";
    }

    @Override
    public String getDescription() {
        return "Create a new structure with specified fields";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "size", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "description", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "packed", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
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
        Integer size = (Integer) arguments.get("size");
        String description = (String) arguments.get("description");
        Boolean packed = (Boolean) arguments.get("packed");

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required")
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        DataType existingType = dtm.getDataType(structureName);
        if (existingType != null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure already exists: " + structureName +
                    "\nUse rename_structure or modify existing structure instead")
                .build();
        }

        int transactionID = currentProgram.startTransaction("Create structure");
        boolean success = false;

        try {
            Structure struct;
            if (size != null && size > 0) {
                struct = new StructureDataType(structureName, size);
            } else {
                struct = new StructureDataType(structureName, 0);
            }

            if (description != null && !description.isEmpty()) {
                struct.setDescription(description);
            }

            if (packed != null) {
                struct.setPackingEnabled(packed);
            }

            Structure createdStruct = (Structure) dtm.addDataType(struct, null);

            success = true;

            StringBuilder output = new StringBuilder();
            output.append(String.format("Successfully created structure '%s'\n", structureName));
            output.append(String.format("Size: %d bytes\n", createdStruct.getLength()));
            if (description != null && !description.isEmpty()) {
                output.append(String.format("Description: %s\n", description));
            }
            output.append(String.format("Packed: %s\n", createdStruct.isPackingEnabled() ? "yes" : "no"));
            output.append("\nUse add_structure_field to add fields to this structure");

            return McpSchema.CallToolResult.builder()
                .addTextContent(output.toString())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create structure: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
