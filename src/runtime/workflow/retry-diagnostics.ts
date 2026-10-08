import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { atomicPrivateWrite } from './storage-files.js';

const sanitizePatterns = [
  /\[SYSTEM\]/gi, /<\|im_start\|>/gi, /<\|im_end\|>/gi,
  /<\/?instructions?>/gi, /<\/?system(?:-[a-z]+)?>/gi, /<\/?anthropic>/gi,
  /Human:\s*\n/gi, /Assistant:\s*\n/gi,
];

/** Keep full diagnostics available without letting a large error exhaust the prompt. */
export function prepareRetryDiagnostic(engagementDir: string, message: string): { context: string; path?: string } {
  let sanitized = message;
  for (const pattern of sanitizePatterns) sanitized = sanitized.replace(pattern, '[FILTERED]');
  const encoded = JSON.stringify({ validationError: sanitized });
  if (encoded.length <= 16_000) return { context: encoded };
  const digest = createHash('sha256').update(encoded).digest('hex');
  const path = join(engagementDir, '.retry-diagnostics', `${digest}.json`);
  atomicPrivateWrite(path, `${encoded}\n`);
  return {
    path,
    context: `${JSON.stringify({ validationErrorPreview: sanitized.slice(0, 8_000) })}\nDiagnostic exceeds the inline limit. Read the complete diagnostic at this exact path: ${JSON.stringify(path)}`,
  };
}
