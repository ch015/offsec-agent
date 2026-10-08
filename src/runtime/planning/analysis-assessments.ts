import { existsSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { z } from 'zod';
import { sourceRangeDelivered } from '../source-delivery.js';
import type { ProviderRuntimeEvent } from '../providers/provider-runtime.js';
import type { AnalysisTask } from './task-planner.js';
import { SecurityAssessmentSchema, validateSecurityAssessments, type SecurityObligation } from './security-obligations.js';
import { readStandardFindings } from '../finding-contract.js';
import { readSharedKnowledge } from '../shared-knowledge.js';
export const ANALYSIS_ASSESSMENTS = '02_file_assessments.json';
const FlowEvidence = z.object({ path: z.string(), lineStart: z.number().int().positive(), lineEnd: z.number().int().positive(), quote: z.string().min(1),
  byteStart: z.number().int().nonnegative().optional(), byteEnd: z.number().int().nonnegative().optional() }).strict()
  .refine(value => (value.byteStart === undefined && value.byteEnd === undefined) || (value.byteStart !== undefined && value.byteEnd !== undefined && value.byteEnd > value.byteStart), 'Both byte boundaries must be supplied together');
export const AnalysisAssessmentsSchema = z.object({
  files: z.array(z.object({ path: z.string(), status: z.enum(['analyzed', 'deferred']),
    rationale: z.string().trim().min(20), evidence: z.array(z.object({ lineStart: z.number().int().positive(), lineEnd: z.number().int().positive(), quote: z.string().min(1) }).strict()),
  }).strict()),
  flows: z.array(z.object({ id: z.string(), status: z.enum(['analyzed', 'deferred']), rationale: z.string().trim().min(20), evidenceFiles: z.array(z.string()).min(1), evidence: z.array(FlowEvidence).default([]) }).strict()),
  securityAssessments: z.array(SecurityAssessmentSchema).optional(),
}).strict();

type AssessmentScope = { target: string; files: readonly string[]; flowIds?: readonly string[]; ranges?: readonly { path: string; lineStart: number; lineEnd: number; byteStart?: number; byteEnd?: number }[]; flows?: readonly { id: string; files: string[] }[];
  securityObligations?: readonly SecurityObligation[]; contextFiles?: readonly string[]; findingIds?: readonly string[] };

export function readAnalysisAssessments(input: AssessmentScope & { directory: string }) {
  return validateAnalysisAssessments({ ...input, contextFiles:[...input.contextFiles ?? [],...assessmentContextFiles(input.directory,input.target)],
    findingIds: assessmentFindingIds(input.directory), value: JSON.parse(readFileSync(join(input.directory, ANALYSIS_ASSESSMENTS), 'utf8')) });
}

/** Host-written exploration inventory, never a model-selected filesystem scope. */
export function assessmentContextFiles(directory:string,target:string):string[] {
  const path=join(directory,'00_source_exploration.json');
  if(!existsSync(path)) return [];
  const value=JSON.parse(readFileSync(path,'utf8'));
  return [...value.sourceFiles ?? [],...value.dependencyFiles ?? []].map((file:string)=>relative(target,file));
}

export function assessmentFindingIds(directory:string):string[] {
  const ids=readStandardFindings(directory).map(f=>f.id),path=join(directory,'00_source_exploration.json');
  const context=existsSync(path) ? JSON.parse(readFileSync(path,'utf8')).sharedKnowledgeContext : undefined;
  if(context) for(const record of readSharedKnowledge(context)) {
    if(record.kind==='finding' && (record.finding as {verdict?:string})?.verdict==='supported') {
      for(const origin of record.contributors ?? []) if(origin.findingId) ids.push(origin.findingId);
    }
  }
  return [...new Set(ids)];
}

export function validateAnalysisAssessments(input: AssessmentScope & { value: unknown }) {
  const value = AnalysisAssessmentsSchema.parse(input.value);
  const errors: string[] = [];
  const expected = new Set(input.files), seen = new Set<string>();
  for (const file of value.files) {
    if (!expected.has(file.path) || seen.has(file.path)) { errors.push(`Analysis ownership mismatch: ${file.path}`); continue; }
    seen.add(file.path);
    if (file.status === 'analyzed') {
      const raw = readFileSync(join(input.target, file.path), 'utf8'), lines = raw.split(/\r?\n/);
      if (raw.length && file.evidence.length === 0) errors.push(`Analyzed file requires source evidence: ${file.path}`);
      const range = input.ranges?.find(range => range.path === file.path);
      for (const evidence of file.evidence) {
        if (range?.byteStart !== undefined && !Buffer.from(raw).subarray(range.byteStart, range.byteEnd).toString('utf8').replace(/\r\n/g, '\n').includes(evidence.quote.replace(/\r\n/g, '\n'))) errors.push(`Analysis quote outside assigned bytes: ${file.path}`);
        if (range && (evidence.lineStart < range.lineStart || evidence.lineEnd > range.lineEnd)) errors.push(`Analysis evidence outside assigned range: ${file.path} (owned ${range.lineStart}-${range.lineEnd})`);
        if (evidence.lineEnd < evidence.lineStart || evidence.lineEnd > lines.length || !lines.slice(evidence.lineStart - 1, evidence.lineEnd).join('\n').includes(evidence.quote.replace(/\r\n/g, '\n'))) errors.push(`Invalid file analysis evidence: ${file.path}:${evidence.lineStart}-${evidence.lineEnd}; read these lines and copy an exact substring, without ellipses or reformatted whitespace`);
      }
    }
  }
  const missing = input.files.filter(file => !seen.has(file));
  if (missing.length) errors.push(`Missing file assessments: ${missing.join(', ')}`);
  const flows = new Set<string>();
  for (const flow of value.flows) {
    if (flows.has(flow.id) || !(input.flowIds ?? []).includes(flow.id)) { errors.push(`Unexpected analysis flow: ${flow.id}`); continue; }
    const assigned = input.flows?.find(assigned => assigned.id === flow.id);
    if (assigned && (flow.evidenceFiles.some(file => !assigned.files.includes(file)) || assigned.files.some(file => !flow.evidenceFiles.includes(file)))) errors.push(`Flow evidence must account for both endpoints: ${flow.id}; expected evidenceFiles=${JSON.stringify(assigned.files)}`);
    if (flow.status === 'analyzed') {
      for (const file of flow.evidenceFiles) {
        if (assigned && !assigned.files.includes(file)) continue;
        const raw = readFileSync(join(input.target, file), 'utf8');
        if (raw.length && !flow.evidence.some(evidence => evidence.path === file)) errors.push(`Flow endpoint requires source evidence: ${flow.id}/${file}`);
      }
      for (const evidence of flow.evidence) {
        if (!flow.evidenceFiles.includes(evidence.path) || (assigned && !assigned.files.includes(evidence.path))) { errors.push(`Flow quote outside assigned endpoints: ${flow.id}/${evidence.path}`); continue; }
        const raw = readFileSync(join(input.target, evidence.path)), lines = raw.toString('utf8').split(/\r?\n/);
        if (evidence.byteStart !== undefined && (evidence.byteEnd! > raw.length || !raw.subarray(evidence.byteStart, evidence.byteEnd).toString('utf8').includes(evidence.quote))) errors.push(`Invalid flow evidence byte range: ${flow.id}/${evidence.path}`);
        if (evidence.lineEnd < evidence.lineStart || evidence.lineEnd > lines.length || !lines.slice(evidence.lineStart - 1, evidence.lineEnd).join('\n').includes(evidence.quote.replace(/\r\n/g, '\n'))) errors.push(`Invalid flow evidence: ${flow.id}/${evidence.path}:${evidence.lineStart}-${evidence.lineEnd}; copy an exact source substring`);
      }
    }
    flows.add(flow.id);
  }
  const missingFlows = (input.flowIds ?? []).filter(id => !flows.has(id));
  if (missingFlows.length) errors.push(`Missing cross-unit flow assessment: ${missingFlows.join(', ')}`);
  if (errors.length) throw new Error(errors.join('\n'));
  const security = validateSecurityAssessments({target:input.target,obligations:input.securityObligations ?? [],assessments:value.securityAssessments,
    allowedFiles:[...new Set([...input.files,...input.contextFiles ?? [],...(input.flows ?? []).flatMap(f=>f.files)])],findingIds:input.findingIds});
  return { value, security, complete: value.files.every(file => file.status === 'analyzed') && value.flows.every(flow => flow.status === 'analyzed') && security.complete };
}

export type AssessmentTask = Pick<AnalysisTask, 'ownedSources' | 'flowResponsibilities' | 'contextRanges' | 'kind' | 'securityObligations'>;

export function validateAssessmentDelivery(request: AssessmentTask, assessments: ReturnType<typeof validateAnalysisAssessments>, target: string, events: readonly ProviderRuntimeEvent[]) {
  const requiredRanges: Array<{path:string;lineStart:number;lineEnd:number;byteStart?:number;byteEnd?:number}> = [...request.ownedSources, ...(request.kind === 'range-bridge' ? request.contextRanges : []),
    ...assessments.value.flows.filter(flow => flow.status === 'analyzed').flatMap(flow => flow.evidence),
    ...assessments.security.rows.flatMap(row=>row.evidence)];
  const missing: string[] = [];
  for (const file of requiredRanges) {
    const path = resolve(target, file.path);
    const receipts = events.filter(event => ['SourceDelivery', 'ValidatedSourceReuse'].includes(event.event) && event.resource === path && event.delivery).map(event => event.delivery!);
    const bytes = file.byteStart !== undefined && file.byteEnd !== undefined ? { byteStart: file.byteStart, byteEnd: file.byteEnd } : undefined;
    if (!sourceRangeDelivered(path, receipts, file.lineStart, file.lineEnd, bytes)) missing.push(`${file.path}:${file.lineStart}-${file.lineEnd}${bytes ? ` (bytes ${bytes.byteStart}-${bytes.byteEnd})` : ''}`);
  }
  if (missing.length) throw new Error(`Missing verified source delivery: ${[...new Set(missing)].join('; ')}; read remaining ranges with read_source or Read before completing`);
}
