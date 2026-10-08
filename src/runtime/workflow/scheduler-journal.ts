import { processIdentity, reconcileProviderProcesses } from '../provider-process.js';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { atomicPrivateWrite, readManagedFile } from './storage-files.js';
import { TerminationUnknownError, type SchedulerEvent } from './task-scheduler.js';

type Journal = { schemaVersion: 1; ownerPid: number; ownerIdentity?: string; ownerId: string; tasks: Record<string, { attempt: number; state: string; reason?: string; retryAt?: number }>; lastDecision?: SchedulerEvent };

export async function schedulerJournal(root: string, notify: (event: SchedulerEvent) => void): Promise<(event: SchedulerEvent) => void> {
  const path = join(root, '.recovery', 'scheduler.json');
  const previous: Journal | undefined = existsSync(path) ? JSON.parse(readManagedFile(root, path).toString()) : undefined;
  if (previous && Object.values(previous.tasks).some(task => ['starting', 'running', 'cancelling', 'termination-unknown'].includes(task.state))) {
    try { await reconcileProviderProcesses(root, previous.ownerPid, previous.ownerIdentity); }
    catch (error) { throw new TerminationUnknownError(`Admission suspended until local provider termination: ${String(error)}`); }
    for (const task of Object.values(previous.tasks)) if (['starting', 'running', 'cancelling', 'termination-unknown'].includes(task.state)) task.state = 'terminated';
    notify({ event: 'SchedulerProcessRecovered', active: 0, target: 1, queued: 0, reason: 'Previous coordinator and local SDK processes terminated; remote usage remains receipt-based' });
  }
  const state: Journal = { schemaVersion: 1, ownerPid: process.pid, ownerIdentity: processIdentity(process.pid), ownerId: randomUUID(), tasks: previous?.tasks ?? {} };
  return event => {
    if (event.unitKey && event.state) state.tasks[event.unitKey] = { attempt: event.attempt ?? 0, state: event.state, reason: event.reason, retryAt: event.retryAt };
    state.lastDecision = event;
    atomicPrivateWrite(path, JSON.stringify(state) + '\n');
    notify(event);
  };
}
