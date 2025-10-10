/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for getting symbol information at a specific address.
 */
public class GetSymbolAtAddressTool implements McpTool {

    @Override
    public String getName() {
        return "get_symbol_at_address";
    }

    @Override
    public String getDescription() {
        return "Get symbol/label information at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null)
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

        SymbolTable symTable = currentProgram.getSymbolTable();

        StringBuilder output = new StringBuilder();
        output.append(String.format("Symbols at %s:\n\n", addr));

        Symbol[] symbols = symTable.getSymbols(addr);
        if (symbols.length == 0) {
            output.append("No symbols defined at this address\n");
        } else {
            Symbol primary = symTable.getPrimarySymbol(addr);

            for (Symbol sym : symbols) {
                boolean isPrimary = sym.equals(primary);
                output.append(String.format("%s %s\n",
                    isPrimary ? "*" : " ",
                    sym.getName()));
                output.append(String.format("  Type: %s\n", sym.getSymbolType()));
                output.append(String.format("  Source: %s\n", sym.getSource()));

                if (sym.isGlobal()) {
                    output.append("  Scope: Global\n");
                } else {
                    output.append(String.format("  Scope: %s\n", sym.getParentNamespace().getName()));
                }

                if (sym.hasReferences()) {
                    int refCount = sym.getReferences().length;
                    output.append(String.format("  References: %d\n", refCount));
                }
                output.append("\n");
            }

            if (primary != null) {
                output.append(String.format("Primary symbol: %s\n", primary.getName()));
            }
        }

        var func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func != null) {
            output.append(String.format("\nFunction: %s\n", func.getName()));
            output.append(String.format("  Entry point: %s\n", func.getEntryPoint()));
            output.append(String.format("  Parameters: %d\n", func.getParameterCount()));
        }

        var data = currentProgram.getListing().getDefinedDataAt(addr);
        if (data != null) {
            output.append(String.format("\nData: %s\n", data.getDataType().getName()));
            if (data.getValue() != null) {
                output.append(String.format("  Value: %s\n", data.getValue()));
            }
        }

        var instr = currentProgram.getListing().getInstructionAt(addr);
        if (instr != null) {
            output.append(String.format("\nInstruction: %s\n", instr.toString()));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }
}
