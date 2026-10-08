export { createOffsecAgent, type OffsecAgent, type OffsecAgentOptions, type OffsecRunInput, type OffsecRunResult, type OffsecResumeOptions } from './api/agent.js';
export type { AgentExecutionOptions, AgentSessionOptions, SessionRunner } from './api/execution.js';
export type { SessionSpec, SessionOutcome } from './runtime/session.js';
export type { PhaseMetrics, PhaseMetricsSink } from './runtime/workflow/phase-metrics.js';
export type { MissionRuntimeOptions } from './runtime/workflow/mission-runtime.js';
// One runtime; assessV2 remains a source-compatible alias.
export { assess, resumeAssess, type AssessInput, type AssessDependencies } from './runtime/missions/assess.js';
export { resumeAssessV2, assessV2, type AssessV2Input, type AssessV2Dependencies, type AssessV2ResumeOptions } from './runtime/missions/assess-v2.js';

export { archiveRun, restoreRunArchive, type RunArchive } from './runtime/workflow/run-archive.js';
export { ResilientArtifactStore, type StorageHealth } from './runtime/workflow/resilient-artifacts.js';
