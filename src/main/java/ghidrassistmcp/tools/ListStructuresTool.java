/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Iterator;
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
 * MCP tool for listing structure definitions in the program.
 */
public class ListStructuresTool implements McpTool {

    @Override
    public String getName() {
        return "list_structures";
    }

    @Override
    public String getDescription() {
        return "List structure definitions in the program";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "pattern", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of(), null, null, null);
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

        String pattern = (String) arguments.get("pattern");
        Integer limit = (Integer) arguments.get("limit");
        Integer offset = (Integer) arguments.get("offset");

        int maxResults = limit != null ? limit : 100;
        int startOffset = offset != null ? offset : 0;

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        StringBuilder output = new StringBuilder();

        if (pattern != null && !pattern.isEmpty()) {
            output.append(String.format("Structures matching '%s':\n\n", pattern));
        } else {
            output.append("All structures:\n\n");
        }

        List<Structure> structures = new ArrayList<>();
        Iterator<DataType> allTypes = dtm.getAllDataTypes();

        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof Structure) {
                if (pattern == null || pattern.isEmpty() ||
                    dt.getName().toLowerCase().contains(pattern.toLowerCase())) {
                    structures.add((Structure) dt);
                }
            }
        }

        structures.sort((a, b) -> a.getName().compareToIgnoreCase(b.getName()));

        int count = 0;
        int totalCount = structures.size();

        for (int i = startOffset; i < structures.size() && count < maxResults; i++) {
            Structure struct = structures.get(i);

            output.append(String.format("%-40s size: %4d bytes, fields: %d\n",
                struct.getName(), struct.getLength(), struct.getNumComponents()));

            if (struct.getDescription() != null && !struct.getDescription().isEmpty()) {
                output.append(String.format("  Description: %s\n", struct.getDescription()));
            }

            String path = struct.getCategoryPath().getPath();
            if (!path.equals("/")) {
                output.append(String.format("  Path: %s\n", path));
            }

            count++;
        }

        if (totalCount == 0) {
            output.append("No structures found\n");
        } else {
            output.append(String.format("\nShowing %d-%d of %d structures\n",
                startOffset + 1,
                Math.min(startOffset + count, totalCount),
                totalCount));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }
}
