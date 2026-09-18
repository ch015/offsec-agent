'use strict';

const fs = require('fs');
const path = require('path');
const { getPluginPath } = require('./platform');

let _configCache = null;

/**
 * ch015.config.json 로드
 */
function loadConfig() {
  if (_configCache) return _configCache;
  const configPath = getPluginPath('ch015.config.json');
  try {
    const raw = fs.readFileSync(configPath, 'utf8');
    _configCache = JSON.parse(raw);
    return _configCache;
  } catch (e) {
    return {};
  }
}

/**
 * 설정값 dot-notation 접근
 */
function getConfig(key, defaultValue) {
  const config = loadConfig();
  const keys = key.split('.');
  let value = config;
  for (const k of keys) {
    if (value == null || typeof value !== 'object') return defaultValue;
    value = value[k];
  }
  return value !== undefined ? value : defaultValue;
}

/**
 * 안전한 JSON 파싱
 */
function safeJsonParse(str, defaultValue = null) {
  try {
    return JSON.parse(str);
  } catch {
    return defaultValue;
  }
}

/**
 * 프로젝트 레벨 감지 (basic / standard / regulated)
 */
function detectProjectLevel(projectDir) {
  const config = loadConfig();
  const detection = config.projectLevel?.detection || {};

  // config는 두 가지 형태를 허용한다:
  //   flat array  : "regulated": ["hipaa", "pci-dss", ...]            (indicators만)
  //   nested obj  : "regulated": { indicators: [...], directories: [...] }
  const normalize = (entry) => {
    if (Array.isArray(entry)) return { indicators: entry, directories: [] };
    if (entry && typeof entry === 'object') {
      return { indicators: entry.indicators || [], directories: entry.directories || [] };
    }
    return { indicators: [], directories: [] };
  };

  const regulated = normalize(detection.regulated);
  const standard = normalize(detection.standard);

  // 디렉터리 기반 체크 (nested 형태에서만 의미)
  for (const dir of regulated.directories) {
    if (fs.existsSync(path.join(projectDir, dir))) return 'regulated';
  }
  for (const dir of standard.directories) {
    if (fs.existsSync(path.join(projectDir, dir))) return 'standard';
  }

  // 의존성/지표 기반 체크 — regulated를 standard보다 우선 (더 강한 스코프)
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf8'));
    const deps = (JSON.stringify(pkg.dependencies || {}) + JSON.stringify(pkg.devDependencies || {})).toLowerCase();
    for (const indicator of regulated.indicators) {
      if (deps.includes(String(indicator).toLowerCase())) return 'regulated';
    }
    for (const indicator of standard.indicators) {
      if (deps.includes(String(indicator).toLowerCase())) return 'standard';
    }
  } catch {}

  return config.projectLevel?.default || 'basic';
}

module.exports = {
  loadConfig,
  getConfig,
  safeJsonParse,
  detectProjectLevel
};
