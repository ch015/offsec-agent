import type { StandardFinding } from './finding-contract.js';
import { readApprovedLiveScenario } from './live-scenario-journal.js';
import { verifyLiveTestReceipt } from './live-test-broker.js';

type RuntimeEvidence = NonNullable<StandardFinding['runtimeEvidence']>;
type ApprovedScenario = ReturnType<typeof readApprovedLiveScenario>['scenario'];
type AdaptiveReceipt = Extract<ReturnType<typeof verifyLiveTestReceipt>, { schemaVersion: '2.0.0' }>;

export function assertRuntimeEvidenceIntact(input: {
  engagementDir: string;
  runtimeEvidence: RuntimeEvidence;
  planSha256?: string;
}): void {
  const primary = verifyLiveTestReceipt({
    engagementDir: input.engagementDir,
    receiptId: input.runtimeEvidence.receiptId,
    scenarioId: input.runtimeEvidence.scenarioId,
    planSha256: input.planSha256,
  });
  assertReceiptCleanupSucceeded(primary, input.runtimeEvidence.receiptId);
  const relatedReceiptIds = input.runtimeEvidence.relatedReceiptIds ?? [];
  if (new Set(relatedReceiptIds).size !== relatedReceiptIds.length) {
    throw new Error('related receipt가 중복됐다');
  }
  if (relatedReceiptIds.includes(input.runtimeEvidence.receiptId)) {
    throw new Error('related receipt에 primary receipt를 중복할 수 없다');
  }
  const related = relatedReceiptIds.map((receiptId) => {
    const receipt = verifyLiveTestReceipt({
      engagementDir: input.engagementDir,
      receiptId,
      planSha256: input.planSha256,
    });
    assertReceiptCleanupSucceeded(receipt, receiptId);
    if (receipt.planSha256 !== primary.planSha256) {
      throw new Error('related receipt의 plan binding이 primary와 다르다');
    }
    let scenario: ApprovedScenario | undefined;
    if (primary.schemaVersion === '2.0.0') {
      if (receipt.schemaVersion !== '2.0.0' || receipt.profileSha256 !== primary.profileSha256) {
        throw new Error('related receipt의 profile binding이 primary와 다르다');
      }
      const approved = readApprovedLiveScenario({
        engagementDir: input.engagementDir,
        scenarioId: receipt.scenarioId,
        profileSha256: receipt.profileSha256,
      });
      if (approved.sha256 !== receipt.scenarioSha256) {
        throw new Error('related receipt의 scenario binding이 다르다');
      }
      scenario = approved.scenario;
    }
    return { receipt, scenario };
  });
  if (primary.schemaVersion !== '2.0.0') return;
  const adaptiveRelated = related.flatMap(({ receipt, scenario }) =>
    receipt.schemaVersion === '2.0.0' ? [{ receipt, scenario }] : []);
  const approved = readApprovedLiveScenario({
    engagementDir: input.engagementDir,
    scenarioId: primary.scenarioId,
    profileSha256: primary.profileSha256,
  });
  if (approved.sha256 !== primary.scenarioSha256) {
    throw new Error('primary receipt의 scenario binding이 다르다');
  }
  const linkedControls = adaptiveRelated.flatMap(({ receipt, scenario }) =>
    scenario && receipt.scenarioId !== primary.scenarioId &&
    scenario.parentScenarioId === primary.scenarioId &&
    scenario.parentReceiptId === primary.receiptId
      ? [{ receipt, scenario }]
      : []);
  if (approved.scenario.negativeControl.required && approved.scenario.oracle.kind !== 'differential') {
    throw new Error('필수 negative control에는 typed differential oracle가 필요하다');
  }
  if (approved.scenario.negativeControl.required && linkedControls.length === 0) {
    throw new Error('필수 negative control이 primary scenario/receipt에 연결되지 않았다');
  }
  if (approved.scenario.oracle.kind === 'differential') {
    const { compareActorId, relation, fields, allowedRequestDelta } = approved.scenario.oracle;
    if (!relation || !fields || !allowedRequestDelta) {
      throw new Error('differential oracle typed comparator가 불완전하다');
    }
    const actorComparisons = compareActorId
      ? linkedControls.filter(({ receipt }) => receipt.actorId === compareActorId)
      : linkedControls;
    const comparisons = actorComparisons.filter(({ receipt, scenario }) =>
      requestDeltaMatches(approved.scenario, scenario, primary, receipt, allowedRequestDelta));
    if (comparisons.length === 0) throw new Error('differential oracle에 연결된 comparison receipt가 없다');
    if (!comparisons.some(({ receipt }) => responseRelationMatches(primary, receipt, fields, relation))) {
      throw new Error(`differential oracle의 ${relation} response 관계가 성립하지 않는다`);
    }
  }
  if (input.runtimeEvidence.reproducibility === 'repeated' &&
      !related.some(({ receipt }) => receipt.scenarioId === primary.scenarioId)) {
    throw new Error('repeated 재현성을 입증하는 동일 scenario receipt가 없다');
  }
  if (input.runtimeEvidence.reproducibility === 'differential' &&
      approved.scenario.oracle.kind !== 'differential') {
    throw new Error('differential 재현성에는 typed differential oracle가 필요하다');
  }
}

function requestDeltaMatches(
  primary: ApprovedScenario,
  comparison: ApprovedScenario,
  primaryReceipt: AdaptiveReceipt,
  comparisonReceipt: AdaptiveReceipt,
  allowed: NonNullable<ApprovedScenario['oracle']['allowedRequestDelta']>,
): boolean {
  if (allowed === 'actor-only') {
    const authChanged = primaryReceipt.sessionId !== comparisonReceipt.sessionId &&
      (primaryReceipt.sessionId !== null || comparisonReceipt.sessionId !== null);
    return primary.actorId !== comparison.actorId && authChanged && same(primary.request, comparison.request);
  }
  if (primary.actorId !== comparison.actorId) return false;
  if (allowed === 'query-only') {
    return same({ ...primary.request, query: undefined }, { ...comparison.request, query: undefined }) &&
      !same(queryEntries(primary.request.query), queryEntries(comparison.request.query));
  }
  return same({ ...primary.request, body: undefined }, { ...comparison.request, body: undefined }) &&
    !same(primary.request.body, comparison.request.body);
}

function responseRelationMatches(
  primary: AdaptiveReceipt,
  comparison: AdaptiveReceipt,
  fields: NonNullable<ApprovedScenario['oracle']['fields']>,
  relation: NonNullable<ApprovedScenario['oracle']['relation']>,
): boolean {
  const equal = fields.map((field) => {
    if (field === 'status') return primary.response.status === comparison.response.status;
    if (field === 'body') return primary.response.bodySha256 === comparison.response.bodySha256;
    return same(primary.response.headers, comparison.response.headers);
  });
  return relation === 'equal' ? equal.every(Boolean) : equal.some((value) => !value);
}

function queryEntries(query: ApprovedScenario['request']['query']): [string, string][] {
  return Object.entries(query ?? {}).sort(([left], [right]) => left.localeCompare(right));
}

function same(left: unknown, right: unknown): boolean {
  return stableJson(left) === stableJson(right);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function assertReceiptCleanupSucceeded(
  receipt: ReturnType<typeof verifyLiveTestReceipt>,
  receiptId: string,
): void {
  if (receipt.schemaVersion === '2.0.0' && receipt.cleanup.required && receipt.cleanup.status !== 'succeeded') {
    throw new Error(`상태변경 runtime evidence의 cleanup이 완료되지 않았다: ${receiptId}`);
  }
}
