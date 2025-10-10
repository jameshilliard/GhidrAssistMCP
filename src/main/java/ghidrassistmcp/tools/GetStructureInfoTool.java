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
 * MCP tool for getting detailed information about a structure.
 */
public class GetStructureInfoTool implements McpTool {

    @Override
    public String getName() {
        return "get_structure_info";
    }

    @Override
    public String getDescription() {
        return "Get detailed information about a structure including all fields";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "structure_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
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

        if (structureName == null || structureName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("structure_name parameter is required")
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Structure struct = findStructure(dtm, structureName);

        if (struct == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Structure not found: " + structureName)
                .build();
        }

        StringBuilder output = new StringBuilder();

        output.append(String.format("Structure: %s\n", struct.getName()));
        output.append(String.format("Size: %d bytes (0x%x)\n", struct.getLength(), struct.getLength()));
        output.append(String.format("Path: %s\n", struct.getCategoryPath().getPath()));
        output.append(String.format("Field count: %d\n", struct.getNumComponents()));

        if (struct.getDescription() != null && !struct.getDescription().isEmpty()) {
            output.append(String.format("Description: %s\n", struct.getDescription()));
        }

        output.append(String.format("Packed: %s\n", struct.isPackingEnabled() ? "yes" : "no"));
        output.append(String.format("Alignment: %d\n", struct.getAlignment()));

        output.append("\nFields:\n");

        DataTypeComponent[] components = struct.getComponents();
        for (DataTypeComponent comp : components) {
            output.append(String.format("  +0x%03x  %-30s  %-20s",
                comp.getOffset(),
                comp.getFieldName() != null ? comp.getFieldName() : "<unnamed>",
                comp.getDataType().getName()));

            if (comp.getLength() > 0) {
                output.append(String.format("  [%d bytes]", comp.getLength()));
            }

            output.append("\n");

            if (comp.getComment() != null && !comp.getComment().isEmpty()) {
                output.append(String.format("         Comment: %s\n", comp.getComment()));
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
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
