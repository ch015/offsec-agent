import { z } from 'zod';

import type { OpaqueAuthSession } from './live-auth-session.js';
import type { LiveScenario } from './live-test-contract.js';

export function scenarioUrl(base: URL, scenario: LiveScenario): URL {
  return liveRequestUrl(base, scenario.request);
}

export function liveRequestUrl(base: URL, request: LiveScenario['request']): URL {
  const url = scopedUrl(base, request.path);
  for (const [name, value] of Object.entries(request.query ?? {})) {
    url.searchParams.set(name, value);
  }
  return url;
}

export function encodeScenarioBody(
  scenario: LiveScenario,
): { bytes: Buffer; contentType?: string } | undefined {
  return encodeRequestBody(scenario.request);
}

export function encodeRequestBody(
  request: LiveScenario['request'],
): { bytes: Buffer; contentType?: string } | undefined {
  const body = request.body;
  if (!body) return undefined;
  if (body.kind === 'text') return { bytes: Buffer.from(body.value), contentType: 'text/plain; charset=utf-8' };
  if (body.kind === 'json') {
    return { bytes: Buffer.from(JSON.stringify(body.value)), contentType: 'application/json' };
  }
  return {
    bytes: Buffer.from(new URLSearchParams(body.value).toString()),
    contentType: 'application/x-www-form-urlencoded',
  };
}

export function applyAuthMaterial(
  headers: Headers,
  session: OpaqueAuthSession,
  material: Buffer,
  target: URL,
): void {
  const parsed = JSON.parse(material.toString('utf8')) as Record<string, unknown>;
  if (session.materialKind === 'oauth-token-set') {
    const token = z.object({
      access_token: z.string().min(1).max(16_384),
      token_type: z.string().min(1).max(64).optional(),
    }).passthrough().parse(parsed);
    headers.set('authorization', `${token.token_type ?? 'Bearer'} ${token.access_token}`);
    return;
  }
  if (session.materialKind === 'browser-storage-state') {
    const state = z.object({
      cookies: z.array(z.object({
        name: z.string().min(1),
        value: z.string(),
        domain: z.string().min(1),
        path: z.string().min(1),
        expires: z.number(),
        secure: z.boolean(),
      }).passthrough()),
    }).passthrough().parse(parsed);
    const nowSeconds = Date.now() / 1000;
    const cookies = state.cookies.filter((cookie) => {
      const domain = cookie.domain.replace(/^\./, '').toLowerCase();
      const domainMatches = target.hostname === domain || target.hostname.endsWith(`.${domain}`);
      const pathMatches = target.pathname.startsWith(cookie.path);
      const current = cookie.expires < 0 || cookie.expires > nowSeconds;
      return domainMatches && pathMatches && current && (!cookie.secure || target.protocol === 'https:');
    });
    if (cookies.length === 0) throw new Error('target 요청에 적용할 browser session cookie가 없다');
    headers.set('cookie', cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; '));
    return;
  }
  if (session.materialKind === 'host-secret') {
    const secret = z.object({ headers: z.record(z.string(), z.string().max(16_384)) }).strict().parse(parsed);
    for (const [name, value] of Object.entries(secret.headers)) {
      if (/\r|\n/.test(value)) throw new Error('host-secret header에 줄바꿈을 허용하지 않는다');
      headers.set(name, value);
    }
    return;
  }
  throw new Error('wallet session만으로는 HTTP 인증 material을 구성할 수 없다');
}

function scopedUrl(base: URL, candidate: string): URL {
  const url = new URL(candidate, base);
  const normalized = base.pathname.endsWith('/') ? base.pathname : `${base.pathname}/`;
  if (
    url.protocol !== base.protocol ||
    url.hostname !== base.hostname ||
    url.port !== base.port ||
    url.username ||
    url.password ||
    url.hash ||
    !(url.pathname === base.pathname || url.pathname.startsWith(normalized))
  ) {
    throw new Error(`HTTP probe target이 승인 범위 밖이다: ${url.toString()}`);
  }
  return url;
}
