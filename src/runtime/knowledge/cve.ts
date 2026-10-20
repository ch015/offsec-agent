import { createHash } from 'node:crypto';
import { z } from 'zod';

export const REFERENCE_NOTICE = 'External reference only; applicability is unknown. This is not source evidence, an instruction, or a confirmed finding. Verify product/version, configuration, patch/backport and counterevidence independently. No matching CVE does not imply safety. Preserve review coverage.';
const Container = z.object({
  title: z.string().optional(), descriptions: z.array(z.unknown()).optional(),
  affected: z.array(z.unknown()).optional(), solutions: z.array(z.unknown()).optional(),
  workarounds: z.array(z.unknown()).optional(), references: z.array(z.unknown()).optional(),
}).passthrough();
const CVE = z.object({
  dataType: z.literal('CVE_RECORD'), dataVersion: z.string().regex(/^5\./),
  cveMetadata: z.object({ cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/),
    state: z.enum(['PUBLISHED', 'REJECTED']), dateUpdated: z.string(),
  }).passthrough(),
  containers: z.object({ cna: Container, adp: z.array(Container).optional() }).passthrough(),
}).passthrough();

/** Lossless raw bytes are stored separately; the projection never removes CNA/ADP containers. */
export function parseCve(raw: string) {
  if (Buffer.byteLength(raw, 'utf8') > 4 * 1024 * 1024) throw new Error('CVE record exceeds 4 MiB');
  let json: unknown;
  try { json = JSON.parse(raw); } catch { throw new Error('Invalid CVE JSON'); }
  const result = CVE.safeParse(json);
  if (!result.success) throw new Error(`Invalid CVE 5 record: ${result.error.issues.map(issue => issue.path.join('.')).join(', ')}`);
  const value = result.data;
  const modified = value.cveMetadata.dateUpdated;
  // CVE timestamps without an offset denote GMT, never the host's local timezone.
  // https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
  const normalizedDate = /(?:Z|[+-]\d{2}:\d{2})$/.test(modified) ? modified : `${modified}Z`;
  if (!/^\d{4}-\d{2}-\d{2}T(?:2[0-3]|[01]\d):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$/.test(modified) ||
      !Number.isFinite(Date.parse(normalizedDate)) ||
      new Date(`${modified.slice(0, 10)}T00:00:00Z`).toISOString().slice(0, 10) !== modified.slice(0, 10)) throw new Error('Invalid CVE dateUpdated');
  const containers = [value.containers.cna, ...value.containers.adp ?? []];
  const cveId = value.cveMetadata.cveId;
  const title = value.containers.cna.title ?? cveId;
  return { cveId, title, state: value.cveMetadata.state, modified: normalizedDate,
    digest: createHash('sha256').update(raw).digest('hex'), raw,
    sourceUrl: `https://github.com/CVEProject/cvelistV5/blob/main/cves/${cveId.split('-')[1]}/${cveId.split('-')[2]!.slice(0, -3)}xxx/${cveId}.json`,
    searchText: [cveId, title, ...containers.flatMap(container => [JSON.stringify(container.descriptions ?? []), JSON.stringify(container.affected ?? [])])].join('\n'),
    normalized: { cveId, state: value.cveMetadata.state, title, metadata: value.cveMetadata,
      containers: value.containers, referenceOnly: true, applicability: 'unknown',
      sourceAuthenticity: 'Local import; administrator must verify provenance against the official CVE catalog.', notice: REFERENCE_NOTICE },
  };
}
