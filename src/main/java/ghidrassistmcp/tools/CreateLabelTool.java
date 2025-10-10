/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for creating labels/symbols at addresses.
 */
public class CreateLabelTool implements McpTool {

    @Override
    public String getName() {
        return "create_label";
    }

    @Override
    public String getDescription() {
        return "Create a label/symbol at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "primary", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "namespace", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "name"), null, null, null);
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
        String name = (String) arguments.get("name");
        Boolean primary = (Boolean) arguments.get("primary");
        String namespaceName = (String) arguments.get("namespace");

        if (addrStr == null || addrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        if (name == null || name.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("name parameter is required")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

        SymbolTable symTable = currentProgram.getSymbolTable();

        int transactionID = currentProgram.startTransaction("Create label");
        boolean success = false;

        try {
            Namespace namespace = currentProgram.getGlobalNamespace();
            if (namespaceName != null && !namespaceName.isEmpty()) {
                var foundNamespace = symTable.getNamespace(namespaceName, null);
                if (foundNamespace != null) {
                    namespace = foundNamespace;
                }
            }

            boolean setPrimary = primary != null ? primary : true;

            var symbol = symTable.createLabel(addr, name, namespace, SourceType.USER_DEFINED);

            if (setPrimary) {
                symbol.setPrimary();
            }

            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully created label '%s' at %s\nPrimary: %s",
                    name, addr, symbol.isPrimary() ? "yes" : "no"))
                .build();

        } catch (InvalidInputException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid label name: " + e.getMessage())
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create label: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
