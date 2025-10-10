/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for listing bookmarks and analysis notes.
 */
public class ListBookmarksTool implements McpTool {

    @Override
    public String getName() {
        return "list_bookmarks";
    }

    @Override
    public String getDescription() {
        return "List bookmarks and analysis notes in the program";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "type", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null)
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

        String typeFilter = (String) arguments.get("type");
        String addrStr = (String) arguments.get("address");
        Integer limit = (Integer) arguments.get("limit");

        int maxResults = limit != null ? limit : 100;

        BookmarkManager bookmarkMgr = currentProgram.getBookmarkManager();

        StringBuilder output = new StringBuilder();

        if (addrStr != null && !addrStr.isEmpty()) {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            if (addr == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address format: " + addrStr)
                    .build();
            }

            output.append(String.format("Bookmarks at %s:\n\n", addr));

            Bookmark[] bookmarks = bookmarkMgr.getBookmarks(addr);
            if (bookmarks.length == 0) {
                output.append("No bookmarks at this address\n");
            } else {
                for (Bookmark bm : bookmarks) {
                    output.append(String.format("[%s] %s\n", bm.getTypeString(), bm.getCategory()));
                    if (bm.getComment() != null && !bm.getComment().isEmpty()) {
                        output.append(String.format("  %s\n", bm.getComment()));
                    }
                    output.append("\n");
                }
            }
        } else {
            String[] types;
            if (typeFilter != null && !typeFilter.isEmpty()) {
                types = new String[] { typeFilter };
                output.append(String.format("Bookmarks of type '%s':\n\n", typeFilter));
            } else {
                BookmarkType[] bookmarkTypes = bookmarkMgr.getBookmarkTypes();
                types = new String[bookmarkTypes.length];
                for (int i = 0; i < bookmarkTypes.length; i++) {
                    types[i] = bookmarkTypes[i].getTypeString();
                }
                output.append("All bookmarks:\n\n");

                if (types.length == 0) {
                    output.append("No bookmarks in program\n");
                    return McpSchema.CallToolResult.builder()
                        .addTextContent(output.toString())
                        .build();
                }

                output.append("Bookmark types: ");
                for (int i = 0; i < types.length; i++) {
                    if (i > 0) output.append(", ");
                    output.append(types[i]);
                    int count = bookmarkMgr.getBookmarkCount(types[i]);
                    output.append(String.format("(%d)", count));
                }
                output.append("\n\n");
            }

            int totalCount = 0;
            for (String type : types) {
                var iter = bookmarkMgr.getBookmarksIterator(type);

                while (iter.hasNext() && totalCount < maxResults) {
                    Bookmark bm = iter.next();
                    output.append(String.format("@ %s [%s]", bm.getAddress(), bm.getTypeString()));

                    if (bm.getCategory() != null && !bm.getCategory().isEmpty()) {
                        output.append(String.format(" %s", bm.getCategory()));
                    }
                    output.append("\n");

                    if (bm.getComment() != null && !bm.getComment().isEmpty()) {
                        String comment = bm.getComment();
                        if (comment.length() > 200) {
                            comment = comment.substring(0, 197) + "...";
                        }
                        output.append(String.format("  %s\n", comment));
                    }

                    var func = currentProgram.getFunctionManager().getFunctionContaining(bm.getAddress());
                    if (func != null) {
                        output.append(String.format("  In function: %s\n", func.getName()));
                    }

                    output.append("\n");
                    totalCount++;
                }
            }

            if (totalCount == 0) {
                output.append("No bookmarks found\n");
            } else if (totalCount == maxResults) {
                output.append(String.format("Showing first %d bookmarks (limit reached)\n", maxResults));
            } else {
                output.append(String.format("Total: %d bookmarks\n", totalCount));
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(output.toString())
            .build();
    }
}
