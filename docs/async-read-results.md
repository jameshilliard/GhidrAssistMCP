# Fast asynchronous reads

With asynchronous execution enabled, read-only long-running tools wait up to
250 milliseconds for their submitted job to reach a terminal state. Fast reads
return the complete result directly, avoiding a separate status request.
Operations still running return the same job's compact handle. Use its `task_id`
with `get_task_status` to retrieve completion, or `cancel_task` to cancel.

An elapsed or interrupted observation window does not restart or cancel the job.
The worker retains its program lease until it stops, including after a later
cancellation request. Responses use the program context captured at submission,
with the context banner applied once.

Clients should handle both a final result and a pending handle from an
asynchronous read. Mutation tools keep their existing immediate-handle behavior.
