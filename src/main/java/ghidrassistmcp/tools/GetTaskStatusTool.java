/*
 * MCP tool for getting task status.
 */
package ghidrassistmcp.tools;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets the status of an async task or retrieves its result.
 */
public class GetTaskStatusTool implements McpTool {

    private static final int MAX_WAIT_MS = 30000;

    @Override
    public String getName() {
        return "get_task_status";
    }

    @Override
    public String getDescription() {
        return "Get an async task's status or completed result, optionally waiting up to wait_ms for completion";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "task_id", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "wait_ms", Map.of("type", "integer", "minimum", 0, "maximum", MAX_WAIT_MS,
                    "default", 0, "description", "Wait up to this many milliseconds for this task to finish; timeout or interruption returns its current status without cancelling it")
            ),
            List.of("task_id"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("Task status requires backend reference. Use execute with backend parameter.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (!(arguments.get("task_id") instanceof String taskId) || taskId.isBlank()) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("task_id parameter is required and must be a non-empty string")
                .build();
        }

        int waitMillis = 0;
        if (arguments.containsKey("wait_ms")) {
            try {
                if (!(arguments.get("wait_ms") instanceof Number number)) {
                    throw new IllegalArgumentException();
                }
                waitMillis = new BigDecimal(number.toString()).intValueExact();
                if (waitMillis < 0 || waitMillis > MAX_WAIT_MS) {
                    throw new IllegalArgumentException();
                }
            } catch (IllegalArgumentException | ArithmeticException invalidWait) {
                return McpSchema.CallToolResult.builder()
                    .isError(true)
                    .addTextContent("wait_ms must be an integer between 0 and " + MAX_WAIT_MS)
                    .build();
            }
        }

        var taskManager = backend.getTaskManager();
        if (taskManager == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Task manager not available")
                .build();
        }

        McpTask task = taskManager.getTask(taskId);
        if (task == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Task not found: " + taskId)
                .build();
        }

        if (waitMillis > 0 && !task.isTerminal()) {
            try {
                task.awaitCompletion(waitMillis);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }

        return taskManager.getTaskResult(taskId);
    }
}
