/** Canonical source assessment entrypoint. The retired v1 engine is not executable. */
export { assessV2 as assess, resumeAssessV2 as resumeAssess, type AssessV2Input as AssessInput, type AssessV2Dependencies as AssessDependencies } from './assess-v2.js';
import { runAssessCli } from './assess-v2.js';
if (import.meta.url === `file://${process.argv[1]}`) {
  runAssessCli().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
