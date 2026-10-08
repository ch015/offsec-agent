import { describe, expect, it } from 'vitest';
import { scoreDiagnosticQuality, type DiagnosticQualityInput, type DiagnosticJudgment } from '../diagnostic-quality.js';

const reason = 'Independently checked the active source and the applicable request conditions.';
const judgment = (predictionId: string, causeId: string): DiagnosticJudgment => ({ predictionId, causeId, decision:'known-valid', duplicateOf:null, sourceEvidenceValid:true, conditionsValid:true, rationale:reason });
const baseline = (): DiagnosticQualityInput => ({project:'test',runId:'run-01',truthCauseIds:['a','b'],predictionIds:['1','2'],judgments:[judgment('1','a'),judgment('2','b')],negativeControls:[{id:'fixed-a',result:'pass',rationale:reason}],executionComplete:true,sourceDeliveryComplete:true,independentCountingComplete:true,frozenTruthVerified:true});

describe('internal independent-cause diagnostic quality', () => {
  it('requires both precision and recall, exposing misses separately from false positives', () => {
    const input=baseline();input.judgments[1]={...judgment('2','b'),decision:'false-positive',causeId:null};
    const result=scoreDiagnosticQuality(input);
    expect(result).toMatchObject({precision:.5,recall:.5,f1:.5,falsePositives:1,falseNegatives:1,missedCauseIds:['b']});
    expect(result.gate.passed).toBe(false);
  });
  it('accepts the exact 90% boundary without rounding a smaller value up', () => {
    const input=baseline();input.truthCauseIds=Array.from({length:10},(_,i)=>String(i));
    input.judgments=input.truthCauseIds.slice(0,9).map(id=>judgment(id,id));
    input.judgments.push({...judgment('fp','x'),decision:'false-positive',causeId:null});input.predictionIds=input.judgments.map(row=>row.predictionId);
    expect(scoreDiagnosticQuality(input)).toMatchObject({precision:.9,recall:.9,gate:{passed:true}});
    input.precisionThreshold=.90000001;expect(scoreDiagnosticQuality(input).gate.passed).toBe(false);
  });
  it('does not remove unresolved predictions to obtain a passing score', () => {
    const input=baseline();input.judgments.push({...judgment('3','x'),decision:'unresolved',causeId:null});input.predictionIds.push('3');
    expect(scoreDiagnosticQuality(input)).toMatchObject({precision:1,precisionLowerBound:2/3,gate:{passed:false,failures:['unresolved-predictions']}});
  });
  it.each(['sourceEvidenceValid','conditionsValid'] as const)('does not credit a valid-looking label with false %s', flag => {
    const input=baseline();input.judgments[0]![flag]=false;
    expect(scoreDiagnosticQuality(input)).toMatchObject({knownTruePositives:1,invalidAccepted:1,falseNegatives:1,gate:{passed:false}});
  });
  it('counts novel valid causes for precision but preserves the frozen recall denominator', () => {
    const input=baseline();input.judgments[1]={...judgment('2','new'),decision:'novel-valid'};
    expect(scoreDiagnosticQuality(input)).toMatchObject({precision:1,recall:.5,novelTruePositives:1,falseNegatives:1});
  });
  it('rejects repeated root identities instead of inflating independent counts', () => {
    const input=baseline();input.judgments[1]=judgment('2','a');
    expect(()=>scoreDiagnosticQuality(input)).toThrow('counted twice');
    input.judgments[1]={...judgment('2','a'),causeId:null,decision:'duplicate',duplicateOf:'1'};
    expect(scoreDiagnosticQuality(input)).toMatchObject({knownTruePositives:1,duplicates:1,recall:.5});
  });
  it('rejects duplicate cycles, missing judgments and fabricated truth IDs', () => {
    const input=baseline();input.judgments[1]={...judgment('2','b'),causeId:null,decision:'duplicate',duplicateOf:'2'};
    expect(()=>scoreDiagnosticQuality(input)).toThrow('directly');
    input.judgments=[];expect(()=>scoreDiagnosticQuality(input)).toThrow('Every prediction');
    input.judgments=[judgment('1','a'),judgment('2','fabricated')];expect(()=>scoreDiagnosticQuality(input)).toThrow('membership');
  });
  it('leaves precision, recall and F1 undefined for a clean negative-only run', () => {
    const input=baseline();input.truthCauseIds=[];input.predictionIds=[];input.judgments=[];
    expect(scoreDiagnosticQuality(input)).toMatchObject({precision:null,recall:null,f1:null,gate:{passed:true}});
    input.predictionIds=['fp'];input.judgments=[{...judgment('fp','x'),decision:'false-positive',causeId:null}];
    expect(scoreDiagnosticQuality(input)).toMatchObject({precision:0,recall:null,gate:{passed:false}});
  });
  it.each(['executionComplete','sourceDeliveryComplete','independentCountingComplete','frozenTruthVerified'] as const)('rejects numerically perfect scores when %s is false', flag => {
    const input=baseline();input[flag]=false;
    expect(scoreDiagnosticQuality(input)).toMatchObject({precision:1,recall:1,gate:{passed:false}});
  });
  it('requires actually assessed negative controls and rejects any failed or unresolved control', () => {
    const input=baseline();input.negativeControls=[];expect(scoreDiagnosticQuality(input).gate.passed).toBe(false);
    for(const result of ['fail','unresolved'] as const) {
      input.negativeControls=[{id:'fixed',result,rationale:reason}];expect(scoreDiagnosticQuality(input).gate.passed).toBe(false);
    }
  });
});
