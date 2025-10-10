/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for setting pre-instruction comments.
 */
public class SetPreCommentTool implements McpTool {

    @Override
    public String getName() {
        return "set_pre_comment";
    }

    @Override
    public String getDescription() {
        return "Set a pre-instruction comment (before the line)";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "comment", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "comment"), null, null, null);
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
        String comment = (String) arguments.get("comment");

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

        Listing listing = currentProgram.getListing();
        CodeUnit cu = listing.getCodeUnitAt(addr);

        if (cu == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No code unit at address: " + addr)
                .build();
        }

        int transactionID = currentProgram.startTransaction("Set pre comment");
        boolean success = false;

        try {
            cu.setComment(CommentType.PRE, comment);
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully set pre comment at %s", addr))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to set pre comment: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
