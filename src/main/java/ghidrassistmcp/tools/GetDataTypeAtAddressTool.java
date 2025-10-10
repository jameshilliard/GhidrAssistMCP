/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for getting data type information at an address.
 */
public class GetDataTypeAtAddressTool implements McpTool {

    @Override
    public String getName() {
        return "get_datatype_at_address";
    }

    @Override
    public String getDescription() {
        return "Get data type interpretation at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "show_components", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
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
        Boolean showComponents = (Boolean) arguments.get("show_components");

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

        boolean showDetails = showComponents != null ? showComponents : false;

        Data data = currentProgram.getListing().getDefinedDataAt(addr);

        StringBuilder output = new StringBuilder();
        output.append(String.format("Data type at %s:\n\n", addr));

        if (data == null) {
            output.append("No defined data type at this address\n");

            var instr = currentProgram.getListing().getInstructionAt(addr);
            if (instr != null) {
                output.append(String.format("\nThis address contains an instruction: %s\n", instr.toString()));
            } else {
                output.append("\nAddress is undefined (could be uninitialized data or code)\n");
            }
        } else {
            DataType dt = data.getDataType();

            output.append(String.format("Type: %s\n", dt.getDisplayName()));
            output.append(String.format("Category: %s\n", dt.getCategoryPath()));
            output.append(String.format("Size: %d bytes\n", data.getLength()));

            if (data.getValue() != null) {
                output.append(String.format("Value: %s\n", data.getValue()));
            }

            if (data.isPointer()) {
                output.append("Kind: Pointer\n");
                Object value = data.getValue();
                if (value instanceof Address) {
                    Address target = (Address) value;
                    output.append(String.format("Points to: %s\n", target));

                    var targetSym = currentProgram.getSymbolTable().getPrimarySymbol(target);
                    if (targetSym != null) {
                        output.append(String.format("Target symbol: %s\n", targetSym.getName()));
                    }
                }
            } else if (data.isStructure()) {
                output.append("Kind: Structure\n");
            } else if (data.isArray()) {
                output.append("Kind: Array\n");
                output.append(String.format("Element count: %d\n", data.getNumComponents()));
            } else if (data.isUnion()) {
                output.append("Kind: Union\n");
            }

            if (data.hasStringValue()) {
                output.append(String.format("String value: \"%s\"\n", data.getValue()));
            }

            var symbol = currentProgram.getSymbolTable().getPrimarySymbol(addr);
            if (symbol != null) {
                output.append(String.format("\nSymbol: %s\n", symbol.getName()));
            }

            if (showDetails && dt instanceof Structure) {
                Structure struct = (Structure) dt;
                output.append("\nStructure components:\n");
                for (int i = 0; i < struct.getNumComponents(); i++) {
                    var comp = struct.getComponent(i);
                    output.append(String.format("  [+0x%x] %s %s (%d bytes)\n",
                        comp.getOffset(),
                        comp.getDataType().getDisplayName(),
                        comp.getFieldName() != null ? comp.getFieldName() : "",
                        comp.getLength()));
                }
            }

            if (showDetails && dt instanceof Array) {
                Array arr = (Array) dt;
                output.append(String.format("\nArray element type: %s\n", arr.getDataType().getDisplayName()));
                output.append(String.format("Element size: %d bytes\n", arr.getElementLength()));
            }

            if (data.getNumComponents() > 0 && showDetails) {
                output.append(String.format("\nComponents (%d):\n", data.getNumComponents()));
                int limit = Math.min(10, data.getNumComponents());
                for (int i = 0; i < limit; i++) {
                    Data comp = data.getComponent(i);
                    output.append(String.format("  [%d] @ %s: %s = %s\n",
                        i,
                        comp.getAddress(),
                        comp.getDataType().getDisplayName(),
                        comp.getValue() != null ? comp.getValue() : "??"));
                }
                if (data.getNumComponents() > limit) {
                    output.append(String.format("  ... and %d more\n", data.getNumComponents() - limit));
                }
            }

            int refCount = currentProgram.getReferenceManager().getReferenceCountTo(addr);
            if (refCount > 0) {
                output.append(String.format("\nReferenced by %d locations\n", refCount));
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }
}
