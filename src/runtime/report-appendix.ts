import { canonicalV2Findings, resolveV2Review } from './v2-review-resolution.js';
import { assertEvaluationProjection, readEvaluationProjection } from './evaluation-projection.js';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { readManagedFile } from './workflow/storage-files.js';

// Treat source text as text, never active HTML, links or host metadata.
const escape = (value: unknown) => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/([\\`*_{}\[\]()#+.!|~\-])/g, '\\$1');
const quote = (value: unknown) => String(value).split(/\r?\n/).map(line => `> ${escape(line)}`).join('\n');
const field = (label: string, value: unknown) => `**${label}**\n\n${quote(value)}\n`;
const list = (values: readonly string[]) => values.length ? values.join('\n') : '(원장에 기재된 항목 없음)';

function provenance(root: string): string {
  const path = join(root, 'source_manifest.json');
  if (!existsSync(path)) return '';
  const bytes = readManagedFile(root, path), manifest = JSON.parse(bytes.toString());
  const rows = ['\n\n---\n\n## 진단 출처 — 호스트 확정\n',
    '이 기록은 호스트가 봉인한 소스 인벤토리에서 생성했습니다. 본문 초안의 출처 미확인 표기는 이 기록으로 보완됩니다. 실제 분석 바이트는 소스 스냅샷과 그 파일별 해시로 식별합니다.\n',
    field('Source manifest SHA-256', createHash('sha256').update(bytes).digest('hex'))];
  if (manifest.git_head) rows.push(field('Git commit', manifest.git_head), field('Git branch', manifest.git_branch ?? '(기록 없음)'));
  else rows.push('Git 커밋 정보가 없는 소스입니다. 인벤토리와 스냅샷 식별자를 기준으로 합니다.\n');
  const snapshot = join(root, '00_source_snapshot.json');
  if (existsSync(snapshot)) rows.push(field('Source snapshot manifest SHA-256', createHash('sha256').update(readManagedFile(root, snapshot)).digest('hex')));
  return rows.join('\n');
}

/** The reporter owns narrative; the host preserves reviewed IDs and facts. */
export function canonicalFindingAppendix(root: string): string {
  const canonical = canonicalV2Findings(root);
  const source = provenance(root);
  if (!canonical.size) return source;
  assertEvaluationProjection(root);
  const review = resolveV2Review(root), projection = readEvaluationProjection(root);
  const inventory = review.vulnerabilityInventory;
  const sections = [source, '\n\n---\n\n## 확정 판정과 근거 전체 목록 — 호스트 생성\n',
    '이 부록은 확정된 독립 검토와 Finding 원장을 그대로 직렬화한 발행 자료입니다. 새로운 보안 판정이나 실행 증거를 만들지 않습니다. CONFIRMED는 검토자가 채택했다는 뜻이며 동적 재현을 자동으로 의미하지 않습니다. FOLDED_INTO·FALSE_POSITIVE·BACKLOG는 채택 건수에서 제외됩니다.\n',
    `독립 취약점: **${inventory.independentVulnerabilityCount ?? '미확정 — 원인 분류 필요'}** · 채택 기록: **${inventory.acceptedRecordCount}** · 별도 관찰: **${inventory.observationCount}**\n`,
    '독립 취약점은 검토자가 명시한 보안 결함과 독립 수정 경계로 집계합니다. 같은 파일·인용·CWE·제목만으로 합치지 않습니다. 미확정은 0건이 아닙니다.\n',
    ...inventory.causes.flatMap(cause => [
      `### ${escape(cause.causeId)} — 독립 원인\n`,
      field('구성요소', cause.component), field('보안 결함', cause.rootCause), field('독립 수정 경계', cause.fixBoundary),
      field('채택 Finding', list(cause.findingIds)), field('동일 원인 보강 Finding', list(cause.corroboratingFindingIds)),
      field('보정으로 대체된 과거 Finding — 영향 집계에서 제외', list(cause.supersededFindingIds)),
      field('보존된 영향', list(cause.impacts)), field('전제 조건', list(cause.preconditions)), field('미해결 조건', list(cause.unresolved)),
      '**원인 그룹의 근거 전체**\n', ...cause.evidence.map(e => `${quote(`${e.path}:${e.lineStart}-${e.lineEnd}`)}\n>\n${quote(e.quote)}\n`),
    ]),
    ...inventory.observations.map(o => field(`관찰 ${o.findingId} — 독립 취약점에서 제외`, o.reason)),
    ...(inventory.issues.length ? [field('독립 집계 미완료 사유', inventory.issues.map(i => `${i.code} [${i.findingIds.join(', ')}]: ${i.message}`).join('\n'))] : []),
    ...(projection ? [`분류 파일 SHA-256: \`${projection.classificationSha256}\`\n\n평가 입력 파일 SHA-256: \`${projection.inputSha256}\`\n\n두 해시는 서로 다른 파일을 식별합니다.\n`] : []),
    '| Finding ID | 최종 판정 | 원장 심각도 | Confidence | 병합 대표 |\n| --- | --- | --- | --- | --- |',
    ...review.dispositions.map(row => { const finding = canonical.get(row.id)!;
      return `| ${row.id} | ${row.finalStatus} | ${finding.severity} | ${finding.confidence} | ${row.foldedInto ?? '—'} |`; }), ''];
  for (const row of review.dispositions) {
    const f = canonical.get(row.id)!;
    sections.push(`### ${f.id}\n`, field('제목', f.title),
      `판정: **${row.finalStatus}** · 원장 심각도: **${f.severity}** · Confidence: **${f.confidence}**${row.foldedInto ? ` · 병합 대표: **${row.foldedInto}**` : ''}\n`,
      field('검토 사유', row.reason), field('도달 가능성', f.reachability), field('전제 조건', list(f.preconditions)),
      field('영향', f.impact), field('심각도 근거', f.severityRationale), field('보완책', f.remediation),
      field('표준 매핑', list(f.standards)), field('미해결 사항', list(f.unresolved)), '**원문 근거**\n',
      ...f.evidence.map(e => `${quote(`${e.path}:${e.lineStart}-${e.lineEnd}`)}\n>\n${quote(e.quote)}\n`));
  }
  assertEvaluationProjection(root);
  return sections.join('\n') + '\n';
}
