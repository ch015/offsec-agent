import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { extname } from 'node:path';
const require = createRequire(import.meta.url);

export type SourceChange = {
  kind: 'identical' | 'supported-format-only' | 'analysis-relevant' | 'unknown';
  profile: 'source-format/1'; oldDigest: string; newDigest: string;
  reuseAnalysis: boolean; reuseToolOutput: boolean; reason: string;
};
const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const normalized = (text: string) => text.replace(/\r\n/g, '\n').replace(/\n$/, '');

/** Deliberately narrow: EOL/one terminal newline, valid JS/TS/JSON, no literal/raw-data ambiguity. */
export function compareSourceRevision(file: string, before: Uint8Array, after: Uint8Array): SourceChange {
  const base = { profile: 'source-format/1' as const, oldDigest: digest(before), newDigest: digest(after) };
  const result = (kind: SourceChange['kind'], reason: string): SourceChange => ({ ...base, kind, reason,
    reuseAnalysis: kind === 'identical' || kind === 'supported-format-only', reuseToolOutput: kind === 'identical' });
  if (Buffer.from(before).equals(Buffer.from(after))) return result('identical', 'Exact bytes');
  let oldText: string, newText: string;
  try {
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    oldText = decoder.decode(before); newText = decoder.decode(after);
  } catch { return result('unknown', 'Encoding is not validated UTF-8'); }
  if (normalized(oldText) !== normalized(newText)) return result('analysis-relevant', 'Change exceeds EOL/terminal newline profile');
  const extension = extname(file).toLowerCase();
  if (/\ufeff|\r(?!\n)|`|\\\r?\n/.test(oldText + newText)) return result('unknown', 'BOM, raw/multiline literal or line continuation requires review');
  try {
    if (extension === '.json') { JSON.parse(oldText); JSON.parse(newText); }
    else if (['.js', '.mjs', '.cjs', '.ts'].includes(extension)) {
      const Parser = require('tree-sitter');
      const parser = new Parser();
      parser.setLanguage(extension === '.ts' ? require('tree-sitter-typescript').typescript : require('tree-sitter-javascript'));
      for (const text of [oldText, newText]) {
        const tree = parser.parse(text);
        try { if (tree.rootNode.hasError) return result('unknown', 'Syntax errors require review'); }
        finally { tree.delete?.(); }
      }
    } else return result('unknown', 'No verified format profile for this language');
  } catch { return result('unknown', 'Parser unavailable or invalid syntax'); }
  return result('supported-format-only', 'Validated EOL/terminal newline change; tool outputs require independent validation');
}

/** Rebind a quote only when every referenced logical line still matches. Never rewrite old evidence. */
export function mapEvidenceLines(before: string, after: string, start: number, end: number) {
  const oldLines = before.replace(/\r\n/g, '\n').split('\n'), newLines = after.replace(/\r\n/g, '\n').split('\n');
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start || end > oldLines.length || end > newLines.length) return undefined;
  for (let line = start - 1; line < end; line++) if (oldLines[line] !== newLines[line]) return undefined;
  const offsets = (text: string) => {
    const lines = text.split('\n');
    const from = Buffer.byteLength(lines.slice(0, start - 1).map(line => line + '\n').join(''));
    return { byteStart: from, byteEnd: from + Buffer.byteLength(lines.slice(start - 1, end).join('\n')) };
  };
  return { lineStart: start, lineEnd: end, previous: offsets(before), current: offsets(after) };
}
