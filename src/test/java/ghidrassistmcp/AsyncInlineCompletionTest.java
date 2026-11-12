package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

class AsyncInlineCompletionTest {
    private final TestBackend backend = new TestBackend();
    private final CountDownLatch releaseWorker = new CountDownLatch(1);
    private final AtomicInteger consumers = new AtomicInteger();
    private final CountDownLatch allLeasesReleased = new CountDownLatch(1);

    @AfterEach
    void shutdown() {
        releaseWorker.countDown();
        backend.shutdown();
    }

    enum Completion { SUCCESS, ERROR, CANCELLED }

    @ParameterizedTest
    @EnumSource(Completion.class)
    void fastReadReturnsTerminalResultInlineWithOneCapturedContext(Completion completion) {
        backend.current = program("original", "/arm64/original");
        AtomicInteger executions = new AtomicInteger();
        backend.registerTool(new ReadTool() {
            @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
                    GhidrAssistMCPBackend owner, McpTask task) {
                executions.incrementAndGet();
                if (completion == Completion.CANCELLED) task.markCancelled();
                return result(completion == Completion.ERROR);
            }
        });

        var response = backend.callTool("inline_read", Map.of());
        McpTask task = onlyTask();
        assertTrue(task.isTerminal());
        assertEquals(completion != Completion.SUCCESS, Boolean.TRUE.equals(response.isError()));
        assertFalse(response.structuredContent() instanceof Map<?, ?> map && map.containsKey("task_id"));
        assertTrue(text(response).startsWith("[Context] Operating on: original\n\n"));
        assertEquals(1, occurrences(text(response), "[Context]"));
        assertEquals(1, executions.get());
        assertFalse(task.getResult() != null && text(task.getResult()).contains("[Context]"));
        var polled = backend.callTool("get_task_status", Map.of("task_id", task.getTaskId()));
        assertEquals(text(response), text(polled));
        assertEquals(response.isError(), polled.isError());
    }

    @Test
    void slowReadRetainsOneTaskAndProgramLeaseUntilItActuallyFinishes() throws Exception {
        backend.current = program("original", "/arm64/original");
        CountDownLatch entered = new CountDownLatch(1);
        AtomicInteger executions = new AtomicInteger();
        backend.registerTool(new ReadTool() {
            @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                executions.incrementAndGet();
                entered.countDown();
                awaitUninterruptibly(releaseWorker);
                return result(false);
            }
        });

        var handle = backend.callTool("inline_read", Map.of());
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        McpTask task = onlyTask();
        Map<?, ?> fields = assertInstanceOf(Map.class, handle.structuredContent());
        assertEquals(task.getTaskId(), fields.get("task_id"));
        assertEquals("inline_read", fields.get("tool"));
        assertTrue(java.util.Set.of("pending", "running").contains(fields.get("status")));
        assertEquals(1000, fields.get("poll_interval_ms"));
        assertTrue(text(handle).length() < 80, "pending response should omit repeated instructions");
        assertTrue(text(handle).contains(task.getTaskId()), "text-only clients need a pollable ID");
        assertEquals(1, consumers.get(), "worker must retain its own program lease after inline timeout");

        backend.current = program("other", "/x86/other");
        var pending = backend.callTool("get_task_status", Map.of("task_id", task.getTaskId()));
        assertEquals(task.getTaskId(), ((Map<?, ?>) pending.structuredContent()).get("task_id"));
        assertTrue(text(pending).startsWith("[Context] Operating on: original | Active window: other\n\n"));
        releaseWorker.countDown();
        assertTrue(task.awaitCompletion(2000));
        assertTrue(allLeasesReleased.await(2, TimeUnit.SECONDS));
        var completed = backend.callTool("get_task_status", Map.of("task_id", task.getTaskId()));
        assertTrue(text(completed).endsWith("complete"));
        assertEquals(1, occurrences(text(completed), "[Context]"));
        assertEquals(1, executions.get());
        assertSame(task, onlyTask());
    }

    @Test
    void cancellingAfterInlineTimeoutDoesNotReleaseAStillRunningProgram() throws Exception {
        backend.current = program("original", "/arm64/original");
        backend.registerTool(new ReadTool() {
            @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                awaitUninterruptibly(releaseWorker);
                return result(false);
            }
        });
        backend.callTool("inline_read", Map.of());
        McpTask task = onlyTask();
        assertTrue(backend.getTaskManager().cancelTask(task.getTaskId()));
        assertTrue(task.awaitCompletion(0));
        assertEquals(1, consumers.get());
        assertTrue(backend.callTool("get_task_status", Map.of("task_id", task.getTaskId())).isError());
        releaseWorker.countDown();
        assertTrue(allLeasesReleased.await(2, TimeUnit.SECONDS));
        assertEquals(0, consumers.get());
    }

    @Test
    void interruptedObservationReturnsTheSameLiveTaskAndRestoresInterrupt() throws Exception {
        backend.current = program("original", "/arm64/original");
        CountDownLatch entered = new CountDownLatch(1);
        AtomicBoolean restored = new AtomicBoolean();
        backend.registerTool(new ReadTool() {
            @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                entered.countDown();
                awaitUninterruptibly(releaseWorker);
                return result(false);
            }
        });
        try (var caller = Executors.newSingleThreadExecutor()) {
            var response = caller.submit(() -> {
                Thread.currentThread().interrupt();
                var handle = backend.callTool("inline_read", Map.of());
                restored.set(Thread.currentThread().isInterrupted());
                return handle;
            }).get(2, TimeUnit.SECONDS);
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            McpTask task = onlyTask();
            assertTrue(restored.get());
            assertFalse(task.isTerminal());
            assertEquals(task.getTaskId(), ((Map<?, ?>) response.structuredContent()).get("task_id"));
            assertEquals(1, consumers.get());
            releaseWorker.countDown();
            assertTrue(task.awaitCompletion(2000));
        }
    }

    private McpTask onlyTask() {
        var tasks = backend.getTaskManager().listTasks(null);
        assertEquals(1, tasks.size());
        return tasks.get(0);
    }

    private Program program(String name, String path) {
        DomainFile file = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[] {DomainFile.class}, (proxy, method, args) -> switch (method.getName()) {
                case "getPathname" -> path;
                case "getFileID" -> path;
                default -> throw new UnsupportedOperationException(method.getName());
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] {Program.class}, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getDomainFile" -> file;
                case "addConsumer" -> { consumers.incrementAndGet(); yield true; }
                case "release" -> {
                    if (consumers.decrementAndGet() == 0) allLeasesReleased.countDown();
                    yield null;
                }
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }

    private static McpSchema.CallToolResult result(boolean error) {
        return McpSchema.CallToolResult.builder().addTextContent(error ? "expected failure" : "complete")
            .isError(error).build();
    }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().get(0)).text();
    }

    private static int occurrences(String value, String search) {
        return (value.length() - value.replace(search, "").length()) / search.length();
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        boolean interrupted = false;
        try {
            while (true) {
                try { latch.await(); return; }
                catch (InterruptedException e) { interrupted = true; }
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static final class TestBackend extends GhidrAssistMCPBackend {
        private volatile Program current;
        @Override public Program getCurrentProgram() { return current; }
    }

    private static class ReadTool implements McpTool {
        @Override public String getName() { return "inline_read"; }
        @Override public String getDescription() { return "Inline read fixture"; }
        @Override public boolean isLongRunning() { return true; }
        @Override public McpSchema.JsonSchema getInputSchema() {
            return new McpSchema.JsonSchema("object", Map.of(), List.of(), false, null, null);
        }
        @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
            return result(false);
        }
    }
}
