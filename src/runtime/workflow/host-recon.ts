/**
 * #12B: Host-level Recon — 보안 표면 분류.
 *
 * Source manifest + dependency graph를 분석하여 프로젝트의 보안 표면을 분류한다.
 * entry points, trust boundaries, security-critical paths를 식별하여
 * downstream(work plan, unit VA)에서 우선순위로 활용 가능하게 한다.
 *
 * 현재 구현: 결정론적 heuristic (LLM 호출 없이).
 * 향후: LLM 기반 deep classification으로 확장 가능.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';

export interface HostReconResult {
  /** entry point로 식별된 파일 경로 */
  entryPoints: string[];
  /** 인증/인가 관련 파일 */
  authSurface: string[];
  /** 데이터 접근 계층 파일 */
  dataSurface: string[];
  /** 외부 네트워크 통신 파일 */
  networkSurface: string[];
  /** 설정/시크릿 관련 파일 */
  configSurface: string[];
  /** 분류되지 않은 일반 파일 */
  general: string[];
}

const ENTRY_POINT_PATTERNS = [
  /\b(server|app|main|index|handler|worker|entry)\b/i,
  /\brouter\b/i,
  /\bapi\//i,
  /\broutes?\//i,
];

const AUTH_PATTERNS = [
  /\b(auth|login|session|token|jwt|oauth|credential|password|secret)\b/i,
  /\bmiddleware\b.*\b(auth|session|token)\b/i,
];

const DATA_PATTERNS = [
  /\b(db|database|query|model|schema|migration|repository|store)\b/i,
  /\b(sql|prisma|sequelize|typeorm|knex|mongo)\b/i,
];

const NETWORK_PATTERNS = [
  /\b(fetch|axios|http|request|client|api-client|webhook)\b/i,
  /\b(socket|websocket|grpc|rpc)\b/i,
];

const CONFIG_PATTERNS = [
  /\b(config|env|setting|secret|key|credential)\b/i,
  /\.env/,
];

/**
 * Source manifest의 파일 목록을 보안 표면별로 분류한다.
 * 결정론적 heuristic 기반 — 파일 경로 패턴 매칭.
 */
export function runHostRecon(input: {
  target: string;
  sourceFiles: readonly string[];
}): HostReconResult {
  const result: HostReconResult = {
    entryPoints: [],
    authSurface: [],
    dataSurface: [],
    networkSurface: [],
    configSurface: [],
    general: [],
  };

  for (const file of input.sourceFiles) {
    let classified = false;

    if (ENTRY_POINT_PATTERNS.some((p) => p.test(file))) {
      result.entryPoints.push(file);
      classified = true;
    }
    if (AUTH_PATTERNS.some((p) => p.test(file))) {
      result.authSurface.push(file);
      classified = true;
    }
    if (DATA_PATTERNS.some((p) => p.test(file))) {
      result.dataSurface.push(file);
      classified = true;
    }
    if (NETWORK_PATTERNS.some((p) => p.test(file))) {
      result.networkSurface.push(file);
      classified = true;
    }
    if (CONFIG_PATTERNS.some((p) => p.test(file))) {
      result.configSurface.push(file);
      classified = true;
    }
    if (!classified) {
      result.general.push(file);
    }
  }

  return result;
}
