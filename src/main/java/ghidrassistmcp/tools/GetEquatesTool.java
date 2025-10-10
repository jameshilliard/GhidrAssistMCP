/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for getting equate (symbolic constant) information.
 */
public class GetEquatesTool implements McpTool {

    @Override
    public String getName() {
        return "get_equates";
    }

    @Override
    public String getDescription() {
        return "Get equates (symbolic names for constants) by value or name";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "value", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
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

        String valueStr = (String) arguments.get("value");
        String name = (String) arguments.get("name");
        Integer limit = (Integer) arguments.get("limit");

        int maxResults = limit != null ? limit : 100;

        EquateTable equateTable = currentProgram.getEquateTable();

        StringBuilder output = new StringBuilder();

        if (valueStr != null && !valueStr.isEmpty()) {
            long value;
            try {
                if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                    value = Long.parseUnsignedLong(valueStr.substring(2), 16);
                } else {
                    value = Long.parseLong(valueStr);
                }
            } catch (NumberFormatException e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid value format. Use decimal or hex with 0x prefix")
                    .build();
            }

            output.append(String.format("Equates for value 0x%X (%d):\n\n", value, value));

            List<Equate> equates = equateTable.getEquates(value);
            if (equates.isEmpty()) {
                output.append("No equates defined for this value\n");
            } else {
                for (Equate eq : equates) {
                    output.append(String.format("- %s = 0x%X (%d)\n",
                        eq.getName(), eq.getValue(), eq.getValue()));
                    output.append(String.format("  References: %d\n", eq.getReferenceCount()));
                }
            }
        } else if (name != null && !name.isEmpty()) {
            output.append(String.format("Equate: %s\n\n", name));

            Equate equate = equateTable.getEquate(name);
            if (equate == null) {
                output.append("Equate not found\n");
            } else {
                output.append(String.format("Name: %s\n", equate.getName()));
                output.append(String.format("Value: 0x%X (%d)\n", equate.getValue(), equate.getValue()));
                output.append(String.format("References: %d\n", equate.getReferenceCount()));

                var refs = equate.getReferences();
                if (refs.length > 0) {
                    output.append("\nUsed at:\n");
                    int count = 0;
                    for (var ref : refs) {
                        if (count >= 10) {
                            output.append(String.format("  ... and %d more\n", refs.length - count));
                            break;
                        }
                        output.append(String.format("  %s (operand %d)\n",
                            ref.getAddress(), ref.getOpIndex()));
                        count++;
                    }
                }
            }
        } else {
            output.append("All equates:\n\n");

            var equates = equateTable.getEquates();
            List<Equate> equateList = new ArrayList<>();
            while (equates.hasNext() && equateList.size() < maxResults) {
                equateList.add(equates.next());
            }

            if (equateList.isEmpty()) {
                output.append("No equates defined in program\n");
            } else {
                for (Equate eq : equateList) {
                    output.append(String.format("%-30s = 0x%08X (%d refs)\n",
                        eq.getName(), eq.getValue(), eq.getReferenceCount()));
                }

                if (equates.hasNext()) {
                    output.append(String.format("\n... and more (showing first %d)\n", maxResults));
                }
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }
}
