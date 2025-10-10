/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for applying a data type at a specific address.
 */
public class ApplyDataTypeTool implements McpTool {

    @Override
    public String getName() {
        return "apply_datatype";
    }

    @Override
    public String getDescription() {
        return "Apply a data type at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "datatype_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "clear_existing", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of("address", "datatype_name"), null, null, null);
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
        String datatypeName = (String) arguments.get("datatype_name");
        Boolean clearExisting = (Boolean) arguments.get("clear_existing");

        if (addrStr == null || addrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        if (datatypeName == null || datatypeName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("datatype_name parameter is required")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

        boolean shouldClear = clearExisting != null ? clearExisting : false;

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataType dataType = null;

        dataType = dtm.getDataType(datatypeName);

        if (dataType == null) {
            dataType = findDataTypeByName(dtm, datatypeName);
        }

        if (dataType == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Data type not found: " + datatypeName + "\nTry using full path like '/byte' or 'pointer'")
                .build();
        }

        int transactionID = currentProgram.startTransaction("Apply data type");
        boolean success = false;

        try {
            Listing listing = currentProgram.getListing();

            if (shouldClear) {
                Data existing = listing.getDefinedDataAt(addr);
                if (existing != null) {
                    listing.clearCodeUnits(addr, addr.add(existing.getLength() - 1), false);
                }
            }

            Data data = listing.createData(addr, dataType);

            StringBuilder output = new StringBuilder();
            output.append(String.format("Applied data type at %s\n\n", addr));
            output.append(String.format("Type: %s\n", dataType.getDisplayName()));
            output.append(String.format("Size: %d bytes\n", data.getLength()));

            if (data.getValue() != null) {
                output.append(String.format("Value: %s\n", data.getValue()));
            }

            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(output.toString())
                .build();

        } catch (CodeUnitInsertionException e) {
            Msg.error(this, "Failed to apply data type", e);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to apply data type: " + e.getMessage() +
                    "\nTry setting clear_existing=true to overwrite existing data")
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }

    private DataType findDataTypeByName(DataTypeManager dtm, String name) {
        String[] searchNames = {
            name,
            "/" + name,
            name.toLowerCase(),
            "/" + name.toLowerCase(),
            "pointer",
            "byte",
            "word",
            "dword",
            "qword",
            "undefined",
            "undefined1",
            "undefined2",
            "undefined4",
            "undefined8"
        };

        for (String searchName : searchNames) {
            if (name.equalsIgnoreCase(searchName)) {
                DataType dt = dtm.getDataType(searchName);
                if (dt != null) {
                    return dt;
                }
            }
        }

        var iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }

        return null;
    }
}
