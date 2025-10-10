/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for creating function definitions.
 */
public class CreateFunctionTool implements McpTool {

    @Override
    public String getName() {
        return "create_function";
    }

    @Override
    public String getDescription() {
        return "Create a function definition at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "end_address", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address"), null, null, null);
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
        String endAddrStr = (String) arguments.get("end_address");

        if (addrStr == null || addrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

        FunctionManager funcMgr = currentProgram.getFunctionManager();

        int transactionID = currentProgram.startTransaction("Create function");
        boolean success = false;

        try {
            Function func;

            if (endAddrStr != null && !endAddrStr.isEmpty()) {
                Address endAddr = currentProgram.getAddressFactory().getAddress(endAddrStr);
                if (endAddr == null) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Invalid end_address format: " + endAddrStr)
                        .build();
                }
                AddressSet body = new AddressSet(addr, endAddr);
                func = funcMgr.createFunction(name, addr, body, SourceType.USER_DEFINED);
            } else {
                func = funcMgr.createFunction(name, addr, null, SourceType.USER_DEFINED);
            }

            success = true;

            StringBuilder output = new StringBuilder();
            output.append(String.format("Successfully created function at %s\n", addr));
            output.append(String.format("Name: %s\n", func.getName()));
            output.append(String.format("Entry point: %s\n", func.getEntryPoint()));
            output.append(String.format("Body: %s\n", func.getBody()));

            return McpSchema.CallToolResult.builder()
                .addTextContent(output.toString())
                .build();

        } catch (InvalidInputException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid function name or address: " + e.getMessage())
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create function: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
