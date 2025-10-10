/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for deleting function definitions.
 */
public class DeleteFunctionTool implements McpTool {

    @Override
    public String getName() {
        return "delete_function";
    }

    @Override
    public String getDescription() {
        return "Delete a function definition";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "function_name", new McpSchema.JsonSchema("string", null, null, null, null, null)
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

        String addrStr = (String) arguments.get("address");
        String functionName = (String) arguments.get("function_name");

        if (addrStr == null && functionName == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Either address or function_name parameter is required")
                .build();
        }

        FunctionManager funcMgr = currentProgram.getFunctionManager();
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
            func = funcMgr.getFunctionAt(addr);
        }

        if (func == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found")
                .build();
        }

        int transactionID = currentProgram.startTransaction("Delete function");
        boolean success = false;

        try {
            String name = func.getName();
            Address entryPoint = func.getEntryPoint();

            funcMgr.removeFunction(entryPoint);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully deleted function '%s' at %s", name, entryPoint))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to delete function: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
