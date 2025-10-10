/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for marking functions as no-return.
 */
public class SetFunctionNoReturnTool implements McpTool {

    @Override
    public String getName() {
        return "set_function_noreturn";
    }

    @Override
    public String getDescription() {
        return "Mark a function as no-return (does not return to caller)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "function_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "noreturn", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of("noreturn"), null, null, null);
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

        String functionName = (String) arguments.get("function_name");
        String addrStr = (String) arguments.get("address");
        Boolean noreturn = (Boolean) arguments.get("noreturn");

        if (functionName == null && addrStr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either function_name or address parameter is required")
                .build();
        }

        Function func = null;

        if (functionName != null && !functionName.isEmpty()) {
            var functions = currentProgram.getFunctionManager().getFunctions(true);
            for (Function f : functions) {
                if (f.getName().equals(functionName)) {
                    func = f;
                    break;
                }
            }
        } else {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            if (addr == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address format: " + addrStr)
                    .build();
            }
            func = currentProgram.getFunctionManager().getFunctionAt(addr);
        }

        if (func == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found")
                .build();
        }

        int transactionID = currentProgram.startTransaction("Set function no-return");
        boolean success = false;

        try {
            func.setNoReturn(noreturn);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully marked function '%s' as %s",
                    func.getName(), noreturn ? "no-return" : "normal return"))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to set function no-return: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
