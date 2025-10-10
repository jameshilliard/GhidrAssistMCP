/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool for reading raw memory contents.
 */
public class ReadMemoryTool implements McpTool {

    @Override
    public String getName() {
        return "read_memory";
    }

    @Override
    public String getDescription() {
        return "Read raw memory contents at a specific address";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "length", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "format", new McpSchema.JsonSchema("string", null, null, null, null, null)
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
        Integer length = (Integer) arguments.get("length");
        String format = (String) arguments.get("format");

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

        int readLength = length != null ? length : 16;
        if (readLength <= 0 || readLength > 4096) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Length must be between 1 and 4096 bytes")
                .build();
        }

        String displayFormat = format != null ? format : "hex";

        Memory memory = currentProgram.getMemory();
        byte[] bytes = new byte[readLength];

        try {
            int bytesRead = memory.getBytes(addr, bytes);
            if (bytesRead == 0) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Unable to read memory at " + addr)
                    .build();
            }

            StringBuilder output = new StringBuilder();
            output.append(String.format("Memory at %s (%d bytes):\n\n", addr, bytesRead));

            if ("hex".equals(displayFormat)) {
                output.append(formatAsHexDump(addr, bytes, bytesRead, currentProgram));
            } else if ("bytes".equals(displayFormat)) {
                output.append(formatAsBytes(bytes, bytesRead));
            } else if ("words".equals(displayFormat)) {
                output.append(formatAsWords(bytes, bytesRead, currentProgram.getLanguage().isBigEndian()));
            } else if ("dwords".equals(displayFormat)) {
                output.append(formatAsDwords(bytes, bytesRead, currentProgram.getLanguage().isBigEndian()));
            } else if ("ascii".equals(displayFormat)) {
                output.append(formatAsAscii(bytes, bytesRead));
            } else if ("disasm".equals(displayFormat)) {
                output.append(formatAsDisassembly(currentProgram, addr, bytesRead));
            } else {
                output.append(formatAsHexDump(addr, bytes, bytesRead, currentProgram));
            }

            return McpSchema.CallToolResult.builder()
                .addTextContent(output.toString())
                .build();

        } catch (MemoryAccessException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Memory access error at " + addr + ": " + e.getMessage())
                .build();
        }
    }

    private String formatAsHexDump(Address baseAddr, byte[] bytes, int length, Program program) {
        StringBuilder sb = new StringBuilder();
        int bytesPerLine = 16;

        for (int i = 0; i < length; i += bytesPerLine) {
            Address lineAddr = baseAddr.add(i);
            sb.append(String.format("%08x: ", lineAddr.getOffset()));

            int lineLen = Math.min(bytesPerLine, length - i);

            for (int j = 0; j < lineLen; j++) {
                if (j == 8) sb.append(" ");
                sb.append(String.format("%02x ", bytes[i + j] & 0xFF));
            }

            for (int j = lineLen; j < bytesPerLine; j++) {
                if (j == 8) sb.append(" ");
                sb.append("   ");
            }

            sb.append(" |");
            for (int j = 0; j < lineLen; j++) {
                byte b = bytes[i + j];
                if (b >= 0x20 && b < 0x7F) {
                    sb.append((char) b);
                } else {
                    sb.append('.');
                }
            }
            sb.append("|\n");

            var data = program.getListing().getDefinedDataAt(lineAddr);
            var instr = program.getListing().getInstructionAt(lineAddr);
            if (data != null) {
                sb.append(String.format("        [%s]\n", data.getDataType().getName()));
            } else if (instr != null) {
                sb.append(String.format("        %s\n", instr.toString()));
            }
        }

        return sb.toString();
    }

    private String formatAsBytes(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            if (i > 0 && i % 16 == 0) sb.append("\n");
            sb.append(String.format("%02X ", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    private String formatAsWords(byte[] bytes, int length, boolean bigEndian) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length - 1; i += 2) {
            if (i > 0 && i % 16 == 0) sb.append("\n");
            int word;
            if (bigEndian) {
                word = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
            } else {
                word = ((bytes[i + 1] & 0xFF) << 8) | (bytes[i] & 0xFF);
            }
            sb.append(String.format("0x%04X ", word));
        }
        return sb.toString();
    }

    private String formatAsDwords(byte[] bytes, int length, boolean bigEndian) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length - 3; i += 4) {
            if (i > 0 && i % 16 == 0) sb.append("\n");
            long dword;
            if (bigEndian) {
                dword = ((long)(bytes[i] & 0xFF) << 24) |
                       ((long)(bytes[i + 1] & 0xFF) << 16) |
                       ((long)(bytes[i + 2] & 0xFF) << 8) |
                       (long)(bytes[i + 3] & 0xFF);
            } else {
                dword = ((long)(bytes[i + 3] & 0xFF) << 24) |
                       ((long)(bytes[i + 2] & 0xFF) << 16) |
                       ((long)(bytes[i + 1] & 0xFF) << 8) |
                       (long)(bytes[i] & 0xFF);
            }
            sb.append(String.format("0x%08X ", dword));
        }
        return sb.toString();
    }

    private String formatAsAscii(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            byte b = bytes[i];
            if (b >= 0x20 && b < 0x7F) {
                sb.append((char) b);
            } else if (b == 0x0A) {
                sb.append('\n');
            } else if (b == 0x0D) {
                sb.append('\r');
            } else if (b == 0x09) {
                sb.append('\t');
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    private String formatAsDisassembly(Program program, Address addr, int length) {
        StringBuilder sb = new StringBuilder();
        var listing = program.getListing();
        Address current = addr;
        Address end = addr.add(length);

        while (current.compareTo(end) < 0) {
            Instruction instr = listing.getInstructionAt(current);
            Data data = listing.getDefinedDataAt(current);

            if (instr != null) {
                sb.append(String.format("%s: %s\n", current, instr.toString()));
                current = current.add(instr.getLength());
            } else if (data != null) {
                sb.append(String.format("%s: %s [%s]\n", current, data.getValue(),
                    data.getDataType().getName()));
                current = current.add(data.getLength());
            } else {
                sb.append(String.format("%s: ?? (undefined)\n", current));
                current = current.add(1);
            }

            if (current.compareTo(end) >= 0) break;
        }

        return sb.toString();
    }
}
