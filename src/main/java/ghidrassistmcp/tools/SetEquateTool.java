/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for setting/creating equates (symbolic names for constants).
 */
public class SetEquateTool implements McpTool {

    @Override
    public String getName() {
        return "set_equate";
    }

    @Override
    public String getDescription() {
        return "Set an equate (symbolic name) for a scalar value at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "operand_index", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "value", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "operand_index", "name", "value"), null, null, null);
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
        String valueStr = (String) arguments.get("value");

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

        if (name == null || name.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("name parameter is required")
                .build();
        }

        if (valueStr == null || valueStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("value parameter is required")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

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

        EquateTable equateTable = currentProgram.getEquateTable();

        int transactionID = currentProgram.startTransaction("Set equate");
        boolean success = false;

        try {
            Equate equate = equateTable.getEquate(name);

            if (equate == null) {
                equate = equateTable.createEquate(name, value);
            } else if (equate.getValue() != value) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent(String.format("Equate '%s' already exists with different value: 0x%X (wanted 0x%X)\nUse rename_equate or delete_equate first",
                        name, equate.getValue(), value))
                    .build();
            }

            equate.addReference(addr, operandIndex);
            success = true;

            StringBuilder output = new StringBuilder();
            output.append(String.format("Successfully set equate '%s' = 0x%X (%d)\n", name, value, value));
            output.append(String.format("Applied at: %s operand %d\n", addr, operandIndex));
            output.append(String.format("Total references: %d\n", equate.getReferenceCount()));

            return McpSchema.CallToolResult.builder()
                .addTextContent(output.toString())
                .build();

        } catch (DuplicateNameException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create equate: " + e.getMessage())
                .build();
        } catch (InvalidInputException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid input: " + e.getMessage())
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to set equate: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
