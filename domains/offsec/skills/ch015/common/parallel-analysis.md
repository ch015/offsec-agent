# Parallel source analysis

The host scheduler owns parallelism. Scanner produces structural responsibility units; the host divides these into TaskRequests containing snapshot identity, exact source ranges, dependency context, flow responsibilities, expected artifacts, and completion criteria.

Analyzer sessions use the shared knowledge store for common dependencies and observations. They preserve finding provenance and avoid resubmitting identical claims. They do not use Agent/Task delegation, execute other phases, or change ownership.

Ready tasks run continuously. Dynamic admission uses actual progress, resource headroom and provider backoff. An explicit user concurrency maximum remains binding. A cancelled worker occupies capacity until local termination is confirmed. Work on a failed task resumes without discarding completed independent tasks.
