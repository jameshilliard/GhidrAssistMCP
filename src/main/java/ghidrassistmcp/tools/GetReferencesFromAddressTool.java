/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for getting references from a specific address.
 */
public class GetReferencesFromAddressTool implements McpTool {

    @Override
    public String getName() {
        return "get_references_from_address";
    }

    @Override
    public String getDescription() {
        return "Get references FROM a specific address (what it points to)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
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
        Integer limit = (Integer) arguments.get("limit");

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

        int maxResults = limit != null ? limit : 100;

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Reference[] references = refMgr.getReferencesFrom(addr);

        StringBuilder output = new StringBuilder();
        output.append(String.format("References FROM %s:\n\n", addr));

        var instr = currentProgram.getListing().getInstructionAt(addr);
        if (instr != null) {
            output.append(String.format("Instruction: %s\n\n", instr.toString()));
        }

        var data = currentProgram.getListing().getDefinedDataAt(addr);
        if (data != null) {
            output.append(String.format("Data: %s", data.getDataType().getName()));
            if (data.getValue() != null) {
                output.append(String.format(" = %s", data.getValue()));
            }
            output.append("\n\n");
        }

        int count = 0;
        int totalCount = references.length;

        for (Reference ref : references) {
            if (count >= maxResults) {
                break;
            }
            Address toAddr = ref.getToAddress();

            output.append(String.format("-> %s", toAddr));

            var symbol = currentProgram.getSymbolTable().getPrimarySymbol(toAddr);
            if (symbol != null) {
                output.append(String.format(" (%s)", symbol.getName()));
            }

            output.append(String.format(" [%s]", ref.getReferenceType().getName()));

            if (ref.getOperandIndex() >= 0) {
                output.append(String.format(" operand %d", ref.getOperandIndex()));
            }

            output.append("\n");

            var targetFunc = currentProgram.getFunctionManager().getFunctionAt(toAddr);
            if (targetFunc != null) {
                output.append(String.format("   Function: %s\n", targetFunc.getName()));
            }

            var targetData = currentProgram.getListing().getDefinedDataAt(toAddr);
            if (targetData != null) {
                output.append(String.format("   Data: %s", targetData.getDataType().getName()));
                if (targetData.getValue() != null) {
                    String valStr = targetData.getValue().toString();
                    if (valStr.length() > 50) {
                        valStr = valStr.substring(0, 47) + "...";
                    }
                    output.append(String.format(" = %s", valStr));
                }
                output.append("\n");
            }

            count++;
        }

        if (totalCount == 0) {
            output.append("No references from this address\n");
        } else if (totalCount > maxResults) {
            output.append(String.format("\nShowing %d of %d references\n", maxResults, totalCount));
        } else {
            output.append(String.format("\nTotal: %d references\n", totalCount));
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }
}
