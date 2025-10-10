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
 * MCP tool for deleting bookmarks.
 */
public class DeleteBookmarkTool implements McpTool {

    @Override
    public String getName() {
        return "delete_bookmark";
    }

    @Override
    public String getDescription() {
        return "Delete a bookmark at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "type", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "category", new McpSchema.JsonSchema("string", null, null, null, null, null)
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
        String type = (String) arguments.get("type");
        String category = (String) arguments.get("category");

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

        BookmarkManager bookmarkMgr = currentProgram.getBookmarkManager();

        int transactionID = currentProgram.startTransaction("Delete bookmark");
        boolean success = false;

        try {
            Bookmark[] bookmarks;

            if (type != null && !type.isEmpty() && category != null && !category.isEmpty()) {
                Bookmark bm = bookmarkMgr.getBookmark(addr, type, category);
                bookmarks = bm != null ? new Bookmark[]{bm} : new Bookmark[0];
            } else {
                bookmarks = bookmarkMgr.getBookmarks(addr);
            }

            if (bookmarks.length == 0) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No bookmarks found at " + addr)
                    .build();
            }

            int count = 0;
            for (Bookmark bm : bookmarks) {
                if (type == null || type.isEmpty() || bm.getTypeString().equals(type)) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        bookmarkMgr.removeBookmark(bm);
                        count++;
                    }
                }
            }

            success = true;

            return McpSchema.CallToolResult.builder()
                .addTextContent(String.format("Successfully deleted %d bookmark(s) at %s", count, addr))
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to delete bookmark: " + e.getMessage())
                .build();
        } finally {
            currentProgram.endTransaction(transactionID, success);
        }
    }
}
