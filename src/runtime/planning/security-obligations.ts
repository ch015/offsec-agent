import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';

export const controlCases = {
  'input-validation': ['missing-null-empty', 'type-and-shape', 'numeric-and-size-boundaries', 'cross-field-consistency'],
  authorization: ['unauthenticated', 'other-owner', 'role-and-http-method', 'upstream-guards'],
  'injection-and-output': ['attacker-controlled-origin', 'transform-and-sink', 'context-specific-defense', 'runtime-preconditions'],
  'state-and-session': ['identity-binding', 'state-transition', 'replay-and-ordering', 'version-and-environment'],
  'configuration-and-secrets': ['deployed-consumer', 'sensitive-values', 'effective-defaults', 'resource-and-dependency-limits'],
  'cross-boundary-flow': ['entry-and-exit', 'guards-and-transforms', 'state-and-identity', 'runtime-preconditions'],
} as const;
export const SecurityControlSchema = z.enum(Object.keys(controlCases) as [keyof typeof controlCases, ...Array<keyof typeof controlCases>]);
export const SecurityObligationSchema = z.object({ id: z.string().regex(/^SO-[a-f0-9]{20}$/),
  control: SecurityControlSchema, files: z.array(z.string()).min(1), surface: z.string().min(1),
  question: z.string().min(20), cases: z.array(z.string()).min(1),
  anchors: z.array(z.object({path:z.string(),lineStart:z.number().int().positive(),lineEnd:z.number().int().positive(),quote:z.string().min(1)})).min(1),
}).strict();
export type SecurityObligation = z.infer<typeof SecurityObligationSchema>;
type Range = {path:string;lineStart:number;lineEnd:number;byteStart?:number;byteEnd?:number};
const questions: Record<keyof typeof controlCases,string> = {
  'input-validation':'Check every input/field in this surface: missing/null/empty/whitespace, type/shape, zero/negative/bounds and related-field consistency. Follow ORM setters and database constraints; client validation is not a server guard.',
  authorization:'Enumerate protected operations and HTTP methods in this surface. Trace registration and upstream middleware, then compare anonymous/ordinary/admin and own/other object access. A GET guard does not prove DELETE protection.',
  'injection-and-output':'Trace attacker-controlled values through transforms into each query, command, path, template or output context. Seek actual escaping/parameterization and version-specific counterevidence, not just suspicious function names.',
  'state-and-session':'Trace identity, session/account binding and state-changing operations across request sequences. Check deletion, ordering, replay, cross-field consistency and relevant version/environment conditions.',
  'configuration-and-secrets':'Determine which configuration or secret has a deployed consumer. Separate fixture documentation from live behavior; check effective defaults, resource limits and dependency/version conditions without guessing exploitability.',
  'cross-boundary-flow':'Trace the assigned connection with evidence at both ends: input/entry, transforms/guards, state/identity and sink/exit. Distinguish syntactic imports from runtime reachability and retain unverified conditions.',
};

/** Conservative surface hints, never vulnerability verdicts. Original source
 * remains mandatory. Groups cover ALL matching occurrences in a source range;
 * anchors illustrate the surface and do not narrow its assigned scope. */
export function createSecurityObligations(target:string, ranges:readonly Range[], interfaces:readonly {file:string;description:string}[] = []): SecurityObligation[] {
  const results:SecurityObligation[]=[];
  for (const range of ranges) {
    const raw=readFileSync(join(target,range.path)), all=raw.toString('utf8').split(/\r?\n/);
    const text=raw.subarray(range.byteStart ?? 0,range.byteEnd ?? raw.length).toString('utf8');
    const seeds:Array<[keyof typeof controlCases,RegExp]> = [
      ['input-validation',/\b(?:req|request)\.(?:body|query|params)|\$_(?:GET|POST|REQUEST)|\b(?:allowNull|validators?|nullable|DataTypes|z\.object|Joi\.)\b|request\.(?:args|form|json)/i],
      ['authorization',/\b(?:app|router|routes?)\.(?:get|post|put|patch|delete|use|all)|\b(?:isAuthorized|isAuthenticated|authorize|auth_required|login_required|IsAuthenticated)\b|\$_(?:GET|POST|REQUEST)|@(?:Get|Post|Put|Delete|Request)Mapping|@\w+\.route/i],
      ['injection-and-output',/\b(?:eval|exec|execute|query|render|sendFile|readFile|writeFile|json[p]?|shell_exec|mysqli_query|mysql_query|include|require_once|unserialize|innerHTML|dangerouslySetInnerHTML|bypassSecurityTrust\w*)\b|\b(?:echo|print)\s+\$|\b(?:req|request)\.(?:body|query|params)/i],
      ['state-and-session',/\b(?:session|jwt|cookie|password|authentication|login|logout|resetPassword|deleteUser|softDelete)\b|\b(?:update|destroy|delete|insert|create|save)\s*\(/i],
      ['configuration-and-secrets',/\b(?:secret|password|api[_-]?key|private[_-]?key|token|dependencies|devDependencies|timeout|rateLimit|cors|csrf|crypto|pragma\s+solidity)\b/i],
    ];
    for (const [control,pattern] of seeds) {
      if (!pattern.test(text)) continue;
      const anchors=[];
      for (let n=range.lineStart;n<=Math.min(range.lineEnd,all.length);n++) {
        const line=all[n-1]!;
        const match=pattern.exec(line);
        if (line.trim() && match && text.includes(line)) {
          const start=Math.max(0,match.index-120);
          anchors.push({path:range.path,lineStart:n,lineEnd:n,quote:line.slice(start,start+800)});
        }
        if (anchors.length===3) break;
      }
      // A split minified line may not be present in full in this range. The
      // quoted range fragment is still bound to its original source line.
      if (!anchors.length && text.trim()) {
        const fragments=text.split(/\r?\n/),offset=fragments.findIndex(line=>line.trim());
        anchors.push({path:range.path,lineStart:range.lineStart+offset,lineEnd:range.lineStart+offset,quote:fragments[offset]!.slice(0,800)});
      }
      if (!anchors.length) continue;
      const surface=interfaces.filter(i=>i.file===range.path).map(i=>i.description).join('; ') || `${range.path}: all matching controls in assigned source range`;
      const id=`SO-${createHash('sha256').update(JSON.stringify([range.path,range.lineStart,control,anchors.map(a=>a.quote.normalize('NFC').replace(/\s+/g,' ').trim())])).digest('hex').slice(0,20)}`;
      results.push({id,control,files:[range.path],surface,question:questions[control],cases:[...controlCases[control]],anchors});
    }
  }
  return results;
}

export const SecurityAssessmentSchema=z.object({id:z.string(),
  cases:z.array(z.object({case:z.string(),result:z.enum(['violated','enforced','not-applicable','unresolved']),reason:z.string().trim().min(20)}).strict()).min(1),
  evidence:z.array(z.object({path:z.string(),lineStart:z.number().int().positive(),lineEnd:z.number().int().positive(),quote:z.string().min(1)}).strict()).min(1),
  findingIds:z.array(z.string()), conditions:z.array(z.string()),
}).strict();

export function validateSecurityAssessments(input:{obligations:readonly SecurityObligation[];assessments:unknown;target:string;allowedFiles:readonly string[];findingIds?:readonly string[]}) {
  const rows=z.array(SecurityAssessmentSchema).parse(input.assessments ?? []), errors:string[]=[];
  const expected=new Map(input.obligations.map(o=>[o.id,o])),seen=new Set<string>();
  for(const row of rows) {
    const obligation=expected.get(row.id);
    if(!obligation || seen.has(row.id)) {errors.push(`Unknown/duplicate security obligation: ${row.id}`);continue;}
    seen.add(row.id);
    const cases=new Set<string>();
    for(const check of row.cases) {
      if(cases.has(check.case) || !obligation.cases.includes(check.case)) errors.push(`Unexpected/duplicate security case: ${row.id}/${check.case}`);
      cases.add(check.case);
    }
    for(const required of obligation.cases) if(!cases.has(required)) errors.push(`Missing security case: ${row.id}/${required}`);
    if(row.cases.some(c=>c.result==='violated') && !row.findingIds.length) errors.push(`Violated control ${row.id} needs a submitted finding or an unresolved outcome.`);
    for(const id of row.findingIds) if(input.findingIds && !input.findingIds.includes(id)) errors.push(`Security assessment ${row.id} references unknown finding ${id}`);
    if(!row.evidence.some(e=>obligation.files.includes(e.path))) errors.push(`Security assessment ${row.id} needs evidence from its assigned surface`);
    for(const ref of row.evidence) {
      if(!input.allowedFiles.includes(ref.path)) {errors.push(`Security evidence outside assigned/context files: ${ref.path}`);continue;}
      const lines=readFileSync(join(input.target,ref.path),'utf8').split(/\r?\n/);
      if(ref.lineEnd<ref.lineStart || ref.lineEnd>lines.length || !lines.slice(ref.lineStart-1,ref.lineEnd).join('\n').includes(ref.quote.replace(/\r\n/g,'\n'))) errors.push(`Invalid security evidence ${row.id}: ${ref.path}:${ref.lineStart}-${ref.lineEnd}`);
    }
  }
  const missing=[...expected.keys()].filter(id=>!seen.has(id));
  if(missing.length) errors.push(`Missing security obligations (${missing.length}): ${missing.join(', ')}`);
  if(errors.length) throw new Error(errors.join('\n'));
  const counts={violated:0,enforced:0,'not-applicable':0,unresolved:0};
  for(const row of rows) for(const check of row.cases) counts[check.result]++;
  return {rows,complete:counts.unresolved===0,counts,totalObligations:expected.size,totalChecks:rows.reduce((n,row)=>n+row.cases.length,0)};
}
