/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.program.model.symbol.EquateTable;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for removing an equate reference from a specific address.
 */
public class RemoveEquateTool implements McpTool {

    @Override
    public String getName() {
        return "remove_equate";
    }

    @Override
    public String getDescription() {
        return "Remove an equate reference from a specific address/operand";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "operand_index", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "operand_index"), null, null, null);
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

        String addrStr = (String) arguments.get("address");
        Integer operandIndex = (Integer) arguments.get("operand_index");
        String name = (String) arguments.get("name");

        if (addrStr == null || addrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        if (operandIndex == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("operand_index parameter is required")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

        EquateTable equateTable = currentProgram.getEquateTable();

        int transactionID = currentProgram.startTransaction("Remove equate");
        boolean success = false;

        try {
            List<Equate> equates;
            if (name != null && !name.isEmpty()) {
                Equate equate = equateTable.getEquate(name);
                if (equate == null) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Equate not found: " + name)
                        .build();
                }
                equates = List.of(equate);
            } else {
                equates = equateTable.getEquates(addr, operandIndex);
            }

            if (equates.isEmpty()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent(String.format("No equate found at %s operand %d", addr, operandIndex))
                    .build();
            }

            StringBuilder output = new StringBuilder();
            for (Equate equate : equates) {
                equate.removeReference(addr, operandIndex);
                output.append(String.format("Removed equate '%s' from %s operand %d\n",
                    equate.getName(), addr, operandIndex));

                if (equate.getReferenceCount() == 0) {
                    equateTable.removeEquate(equate.getName());
                    output.append(String.format("  Equate '%s' had no more references and was deleted\n",
                        equate.getName()));
                } else {
                    output.append(String.format("  Equate '%s' still has %d references\n",
                        equate.getName(), equate.getReferenceCount()));
                }
            }

            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(output.toString())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to remove equate: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
