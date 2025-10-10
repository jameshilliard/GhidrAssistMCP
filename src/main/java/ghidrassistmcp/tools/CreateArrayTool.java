/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for creating array data types at addresses.
 */
public class CreateArrayTool implements McpTool {

    @Override
    public String getName() {
        return "create_array";
    }

    @Override
    public String getDescription() {
        return "Create an array of a specific data type at an address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "data_type", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "element_count", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "clear_existing", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of("address", "data_type", "element_count"), null, null, null);
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
        String dataTypeName = (String) arguments.get("data_type");
        Integer elementCount = (Integer) arguments.get("element_count");
        Boolean clearExisting = (Boolean) arguments.get("clear_existing");

        if (addrStr == null || addrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        if (dataTypeName == null || dataTypeName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("data_type parameter is required")
                .build();
        }

        if (elementCount == null || elementCount < 1) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("element_count parameter is required and must be positive")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType baseType = findDataType(dtm, dataTypeName);

        if (baseType == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Data type not found: " + dataTypeName)
                .build();
        }

        boolean shouldClear = clearExisting != null ? clearExisting : false;

        int transactionID = currentProgram.startTransaction("Create array");
        boolean success = false;

        try {
            Listing listing = currentProgram.getListing();

            if (shouldClear) {
                long arraySize = (long) baseType.getLength() * elementCount;
                listing.clearCodeUnits(addr, addr.add(arraySize - 1), false);
            }

            ArrayDataType arrayType = new ArrayDataType(baseType, elementCount, baseType.getLength());
            Data data = listing.createData(addr, arrayType);

            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully created array at %s\nElement type: %s\nElement count: %d\nTotal size: %d bytes",
                    addr, baseType.getName(), elementCount, data.getLength()))
                .build();

        } catch (CodeUnitInsertionException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create array: " + e.getMessage() +
                    "\nTry setting clear_existing=true to overwrite existing data")
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to create array: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }

    private DataType findDataType(DataTypeManager dtm, String name) {
        DataType dt = dtm.getDataType(name);
        if (dt != null) {
            return dt;
        }

        String[] searchNames = {
            name,
            "/" + name,
            name.toLowerCase(),
            "/" + name.toLowerCase()
        };

        for (String searchName : searchNames) {
            dt = dtm.getDataType(searchName);
            if (dt != null) {
                return dt;
            }
        }

        var iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType candidate = iter.next();
            if (candidate.getName().equalsIgnoreCase(name)) {
                return candidate;
            }
        }

        return null;
    }
}
