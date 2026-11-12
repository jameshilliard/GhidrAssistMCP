# Waiting for asynchronous task results

`get_task_status` accepts an optional integer `wait_ms` from 0 through 30000.
The default is 0, which returns the current task status immediately.

```json
{"task_id":"existing-task-id","wait_ms":30000}
```

A terminal task returns its original result immediately. An ongoing task waits
until success, failure, cancellation, or the requested timeout. Expiry and caller
interruption return the current status without cancelling or restarting the job;
reuse its task ID to retrieve the eventual result. Explicit cancellation remains
available through `cancel_task`.

The result retains the program context captured when the task was submitted,
even if another program becomes active while the caller waits.
