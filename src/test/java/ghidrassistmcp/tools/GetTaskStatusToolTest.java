package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.tasks.McpProgramContext;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

class GetTaskStatusToolTest {
    private final TestBackend backend = new TestBackend();
    private final GetTaskStatusTool tool = new GetTaskStatusTool();
    private final CountDownLatch releaseWorker = new CountDownLatch(1);
    private final AtomicInteger executions = new AtomicInteger();
    private final List<Thread> observers = new ArrayList<>();

    @AfterEach
    void shutdown() throws InterruptedException {
        releaseWorker.countDown();
        for (Thread observer : observers) {
            observer.interrupt();
            observer.join(2000);
        }
        backend.shutdown();
    }

    @Test
    void advertisedSchemaIncludesOptionalBoundedWaitWithZeroDefault() {
        var schema = backend.getAvailableTools().stream()
            .filter(candidate -> candidate.name().equals("get_task_status"))
            .findFirst().orElseThrow().inputSchema();
        Map<?, ?> properties = assertInstanceOf(Map.class, schema.get("properties"));
        Map<?, ?> wait = assertInstanceOf(Map.class, properties.get("wait_ms"));
        assertEquals("integer", wait.get("type"));
        assertEquals(0, wait.get("minimum"));
        assertEquals(30000, wait.get("maximum"));
        assertEquals(0, wait.get("default"));
        assertEquals(List.of("task_id"), schema.get("required"));
        assertFalse(tool.isCacheable());
    }

    @Test
    void omittedOrZeroWaitReturnsCurrentStatusWithoutWaiting() throws Exception {
        McpTask task = blockingTask(ignored -> success());
        for (Map<String, Object> arguments : List.of(
                Map.<String, Object>of("task_id", task.getTaskId()),
                Map.<String, Object>of("task_id", task.getTaskId(), "wait_ms", 0),
                Map.<String, Object>of("task_id", task.getTaskId(), "wait_ms", 0.0),
                Map.<String, Object>of("task_id", task.getTaskId(), "wait_ms", new BigDecimal("0.000")))) {
            assertPending(poll(arguments, false).result().get(2, TimeUnit.SECONDS), task);
        }
        assertOriginalExecutionStillRunning(task);
    }

    @Test
    void completionDuringWaitReturnsTheOriginalCompleteResult() throws Exception {
        McpSchema.CallToolResult expected = success();
        McpTask task = blockingTask(ignored -> expected);
        Poll poll = poll(arguments(task, 30000L), false);
        awaitWaiting(poll);

        releaseWorker.countDown();
        assertSame(expected, poll.result().get(2, TimeUnit.SECONDS));
        assertEquals(McpTask.Status.COMPLETED, task.getStatus());
        assertEquals(1, executions.get());
        assertSame(task, backend.getTaskManager().getTask(task.getTaskId()));
    }

    @Test
    void timeoutKeepsTheSameJobAliveForLaterCompletion() throws Exception {
        McpSchema.CallToolResult expected = success();
        McpTask task = blockingTask(ignored -> expected);
        assertPending(poll(arguments(task, 1), false).result().get(2, TimeUnit.SECONDS), task);
        assertOriginalExecutionStillRunning(task);

        releaseWorker.countDown();
        assertTrue(task.awaitCompletion(2000));
        assertSame(expected, poll(arguments(task, 30000), false).result().get(2, TimeUnit.SECONDS));
        assertEquals(1, executions.get());
    }

    @Test
    void toolErrorDuringWaitIsReturnedIntact() throws Exception {
        McpSchema.CallToolResult expected = McpSchema.CallToolResult.builder()
            .addTextContent("Function not found").isError(true).build();
        McpTask task = blockingTask(ignored -> expected);
        Poll poll = poll(arguments(task, 30000), false);
        awaitWaiting(poll);

        releaseWorker.countDown();
        assertSame(expected, poll.result().get(2, TimeUnit.SECONDS));
        assertEquals(McpTask.Status.FAILED, task.getStatus());
        assertEquals(1, executions.get());
    }

    @Test
    void executionFailureReleasesTheWaiter() throws Exception {
        McpTask task = blockingTask(ignored -> { throw new IllegalStateException("test failure"); });
        Poll poll = poll(arguments(task, 30000), false);
        awaitWaiting(poll);

        releaseWorker.countDown();
        McpSchema.CallToolResult response = poll.result().get(2, TimeUnit.SECONDS);
        assertTrue(Boolean.TRUE.equals(response.isError()));
        assertTrue(text(response).contains("test failure"));
        assertEquals(McpTask.Status.FAILED, task.getStatus());
        assertEquals(1, executions.get());
    }

    @Test
    void explicitCancellationReleasesTheWaiter() throws Exception {
        McpTask task = blockingTask(ignored -> success());
        Poll poll = poll(arguments(task, 30000), false);
        awaitWaiting(poll);

        assertTrue(backend.getTaskManager().cancelTask(task.getTaskId()));
        McpSchema.CallToolResult response = poll.result().get(2, TimeUnit.SECONDS);
        assertTrue(Boolean.TRUE.equals(response.isError()));
        assertTrue(text(response).contains("cancelled"));
        assertEquals(McpTask.Status.CANCELLED, task.getStatus());
        assertEquals(1, executions.get());
        assertSame(task, backend.getTaskManager().getTask(task.getTaskId()));
    }

    @Test
    void interruptionRestoresTheFlagAndOnlyObservesTheExistingJob() throws Exception {
        McpSchema.CallToolResult expected = success();
        McpTask task = blockingTask(ignored -> expected);
        Poll poll = poll(arguments(task, 30000), false);
        awaitWaiting(poll);

        poll.thread().interrupt();
        assertPending(poll.result().get(2, TimeUnit.SECONDS), task);
        assertTrue(poll.interruptedOnReturn().get());
        assertOriginalExecutionStillRunning(task);

        releaseWorker.countDown();
        assertTrue(task.awaitCompletion(2000));
        assertSame(expected, backend.getTaskManager().getTaskResult(task.getTaskId()));
        assertEquals(1, executions.get());
    }

    @Test
    void alreadyCompletedTaskDoesNotWaitForTheRequestedTimeout() throws Exception {
        McpSchema.CallToolResult expected = success();
        McpTask task = blockingTask(ignored -> expected);
        releaseWorker.countDown();
        assertTrue(task.awaitCompletion(2000));

        assertSame(expected, poll(arguments(task, 30000), false).result().get(2, TimeUnit.SECONDS));
    }

    @Test
    void invalidWaitInputsFailWithoutChangingOrReexecutingTheTask() throws Exception {
        McpTask task = blockingTask(ignored -> success());
        List<Object> invalid = new ArrayList<>(List.of(-1, 30001, 1.5, "100", true,
            Double.NaN, Double.POSITIVE_INFINITY, new BigInteger("18446744073709551616"),
            new BigDecimal("1e-1000")));
        invalid.add(null);
        for (Object value : invalid) {
            Map<String, Object> arguments = new LinkedHashMap<>();
            arguments.put("task_id", task.getTaskId());
            arguments.put("wait_ms", value);
            McpSchema.CallToolResult response = poll(arguments, false).result().get(2, TimeUnit.SECONDS);
            assertTrue(Boolean.TRUE.equals(response.isError()), "accepted wait_ms=" + value);
            assertTrue(text(response).contains("wait_ms"));
        }
        assertOriginalExecutionStillRunning(task);
    }

    @Test
    void invalidTaskIdentifiersReturnErrorsRatherThanThrowing() {
        List<Object> invalid = new ArrayList<>(List.of("", "  ", 7, true));
        invalid.add(null);
        for (Object value : invalid) {
            Map<String, Object> arguments = new LinkedHashMap<>();
            arguments.put("task_id", value);
            McpSchema.CallToolResult response = tool.execute(arguments, null, backend);
            assertTrue(Boolean.TRUE.equals(response.isError()));
            assertTrue(text(response).contains("task_id"));
        }
        assertTrue(Boolean.TRUE.equals(tool.execute(Map.of(), null, backend).isError()));
        assertTrue(backend.getTaskManager().listTasks(null).isEmpty());
    }

    @Test
    void missingTaskReturnsImmediatelyEvenWithMaximumWait() throws Exception {
        McpSchema.CallToolResult response = poll(Map.of("task_id", "missing", "wait_ms", 30000), false)
            .result().get(2, TimeUnit.SECONDS);
        assertTrue(Boolean.TRUE.equals(response.isError()));
        assertTrue(text(response).contains("Task not found: missing"));
        assertTrue(backend.getTaskManager().listTasks(null).isEmpty());
    }

    @Test
    void backendWaitPreservesCapturedTaskContextAfterActiveProgramChanges() throws Exception {
        Program original = program("program-a", "/binaries/program-a", "file-a");
        McpProgramContext context = backend.captureProgramContext(original);
        McpTask task = blockingTask(context, ignored -> success());
        backend.activeProgram = program("program-b", "/binaries/program-b", "file-b");
        Poll poll = poll(arguments(task, 30000), true);
        awaitWaiting(poll);

        releaseWorker.countDown();
        McpSchema.CallToolResult response = poll.result().get(2, TimeUnit.SECONDS);
        String message = text(response);
        assertTrue(message.startsWith("[Context] Operating on: program-a | Active window: program-b\n\n"), message);
        assertEquals(1, message.split("\\[Context\\]", -1).length - 1);
        assertTrue(message.endsWith("complete result"));
        assertEquals(context, task.getProgramContext());
        assertFalse(text(task.getResult()).contains("[Context]"));
        assertEquals(1, executions.get());
    }

    private McpTask blockingTask(Function<McpTask, McpSchema.CallToolResult> continuation) throws Exception {
        return blockingTask(McpProgramContext.empty(), continuation);
    }

    private McpTask blockingTask(McpProgramContext context,
            Function<McpTask, McpSchema.CallToolResult> continuation) throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        McpTask task = backend.getTaskManager().submitTask("observed", Map.of(), context, current -> {
            executions.incrementAndGet();
            entered.countDown();
            try {
                if (!releaseWorker.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Worker was not released");
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Worker interrupted", interrupted);
            }
            return continuation.apply(current);
        });
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        return task;
    }

    private Poll poll(Map<String, Object> arguments, boolean throughBackend) {
        AtomicBoolean interrupted = new AtomicBoolean();
        FutureTask<McpSchema.CallToolResult> result = new FutureTask<>(() -> {
            McpSchema.CallToolResult response = throughBackend
                ? backend.callTool("get_task_status", arguments) : tool.execute(arguments, null, backend);
            interrupted.set(Thread.currentThread().isInterrupted());
            return response;
        });
        Thread thread = new Thread(result, "GetTaskStatusToolTest-observer");
        thread.setDaemon(true);
        observers.add(thread);
        thread.start();
        return new Poll(result, thread, interrupted);
    }

    private static void awaitWaiting(Poll poll) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (poll.thread().getState() != Thread.State.TIMED_WAITING && System.nanoTime() < deadline) {
            assertFalse(poll.result().isDone(), "poll returned before the task reached a terminal state");
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
        }
        assertEquals(Thread.State.TIMED_WAITING, poll.thread().getState(), "observer did not enter bounded latch wait");
    }

    private void assertOriginalExecutionStillRunning(McpTask task) {
        assertEquals(McpTask.Status.RUNNING, task.getStatus());
        assertSame(task, backend.getTaskManager().getTask(task.getTaskId()));
        assertEquals(1, executions.get());
        assertEquals(1, backend.getTaskManager().listTasks(null).size());
        assertEquals(1, releaseWorker.getCount());
    }

    private static void assertPending(McpSchema.CallToolResult response, McpTask task) {
        assertFalse(Boolean.TRUE.equals(response.isError()));
        Map<?, ?> metadata = assertInstanceOf(Map.class, response.structuredContent());
        assertEquals(task.getTaskId(), metadata.get("task_id"));
        assertEquals("running", metadata.get("status"));
    }

    private static Map<String, Object> arguments(McpTask task, Number wait) {
        return Map.of("task_id", task.getTaskId(), "wait_ms", wait);
    }

    private static McpSchema.CallToolResult success() {
        return McpSchema.CallToolResult.builder().addTextContent("complete result").build();
    }

    private static String text(McpSchema.CallToolResult response) {
        return response.content().stream().filter(McpSchema.TextContent.class::isInstance)
            .map(McpSchema.TextContent.class::cast).map(McpSchema.TextContent::text)
            .collect(java.util.stream.Collectors.joining("\n"));
    }

    private record Poll(FutureTask<McpSchema.CallToolResult> result, Thread thread,
            AtomicBoolean interruptedOnReturn) { }

    private static final class TestBackend extends GhidrAssistMCPBackend {
        private volatile Program activeProgram;
        @Override public Program getCurrentProgram() { return activeProgram; }
        @Override public List<Program> getAllOpenPrograms() {
            return activeProgram == null ? List.of() : List.of(activeProgram);
        }
    }

    private static Program program(String name, String path, String fileId) {
        DomainFile domainFile = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[] { DomainFile.class }, (proxy, method, arguments) -> switch (method.getName()) {
                case "getName" -> name;
                case "getPathname" -> path;
                case "getFileID" -> fileId;
                case "equals" -> proxy == arguments[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> path;
                default -> throw new UnsupportedOperationException(method.getName());
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] { Program.class },
            (proxy, method, arguments) -> switch (method.getName()) {
                case "getName" -> name;
                case "getDomainFile" -> domainFile;
                case "isClosed" -> false;
                case "addConsumer" -> true;
                case "release" -> null;
                case "equals" -> proxy == arguments[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> name;
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }
}
