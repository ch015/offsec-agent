'use strict';

/**
 * stdin에서 hook 입력 읽기
 */
async function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(data.trim());
    };
    const timer = setTimeout(finish, 5000);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', finish);
  });
}

/**
 * Hook 입력 파싱
 */
function parseHookInput(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return { raw };
  }
}

/**
 * Hook 응답 — 허용
 */
function outputAllow(message) {
  const result = { allow: true };
  if (message) result.message = message;
  process.stdout.write(JSON.stringify(result));
}

/**
 * Hook 응답 — 차단
 */
function outputBlock(reason) {
  process.stdout.write(JSON.stringify({ allow: false, reason }));
}

/**
 * Hook 응답 — 컨텍스트 주입
 * Claude Code의 SessionStart/UserPromptSubmit는 exit 0 시 stdout 평문을 컨텍스트로 주입한다.
 * 기존 {"context": ...} JSON은 인식되지 않는 키라 조용히 무시됐다 → 평문으로 출력.
 */
function outputContext(context) {
  process.stdout.write(String(context == null ? '' : context));
}

/**
 * JSON 응답 출력
 */
function outputJson(data) {
  process.stdout.write(JSON.stringify(data));
}

/**
 * stderr 로그
 */
function logToStderr(...args) {
  process.stderr.write(args.join(' ') + '\n');
}

function withFileLock(targetPath, operation, options = {}) {
  const fs = require('node:fs');
  const lockDir = `${targetPath}.lock`;
  const timeoutMs = options.timeoutMs ?? 5000;
  const staleMs = options.staleMs ?? 30000;
  const started = Date.now();
  const waiter = new Int32Array(new SharedArrayBuffer(4));
  while (true) {
    try {
      fs.mkdirSync(lockDir, { mode: 0o700 });
      break;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try {
        if (Date.now() - fs.statSync(lockDir).mtimeMs > staleMs) {
          fs.rmdirSync(lockDir);
          continue;
        }
      } catch (staleError) {
        if (staleError.code !== 'ENOENT' && staleError.code !== 'ENOTEMPTY') throw staleError;
      }
      if (Date.now() - started >= timeoutMs) throw new Error(`file lock timeout: ${targetPath}`);
      Atomics.wait(waiter, 0, 0, 10);
    }
  }
  try {
    return operation();
  } finally {
    fs.rmdirSync(lockDir);
  }
}

module.exports = {
  readStdin,
  parseHookInput,
  outputAllow,
  outputBlock,
  outputContext,
  outputJson,
  logToStderr,
  withFileLock,
};
