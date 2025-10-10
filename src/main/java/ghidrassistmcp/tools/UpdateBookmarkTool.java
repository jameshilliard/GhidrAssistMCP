/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for updating bookmark comments.
 */
public class UpdateBookmarkTool implements McpTool {

    @Override
    public String getName() {
        return "update_bookmark";
    }

    @Override
    public String getDescription() {
        return "Update a bookmark's comment";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "type", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "category", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "comment", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("address", "type", "category", "comment"), null, null, null);
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
        String type = (String) arguments.get("type");
        String category = (String) arguments.get("category");
        String comment = (String) arguments.get("comment");

        if (addrStr == null || addrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address parameter is required")
                .build();
        }

        if (type == null || type.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("type parameter is required")
                .build();
        }

        if (category == null || category.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("category parameter is required")
                .build();
        }

        Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
        if (addr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addrStr)
                .build();
        }

        BookmarkManager bookmarkMgr = currentProgram.getBookmarkManager();

        int transactionID = currentProgram.startTransaction("Update bookmark");
        boolean success = false;

        try {
            Bookmark bookmark = bookmarkMgr.getBookmark(addr, type, category);

            if (bookmark == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent(String.format("Bookmark not found at %s with type '%s' and category '%s'",
                        addr, type, category))
                    .build();
            }

            bookmarkMgr.setBookmark(addr, type, category, comment != null ? comment : "");
            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully updated bookmark at %s\nType: %s\nCategory: %s",
                    addr, type, category))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to update bookmark: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
