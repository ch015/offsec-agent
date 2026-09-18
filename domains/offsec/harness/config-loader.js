'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const HARNESS_ROOT = __dirname;
const CONFIG_PATH = path.join(HARNESS_ROOT, 'config.yaml');
let configCache = null;

function isSafeRelativeConfigPath(value) {
  if (typeof value !== 'string' || !value || path.isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value)) return false;
  const trimmed = value.replace(/[\\/]+$/, '');
  return Boolean(trimmed) && trimmed.split(/[\\/]/).every((part) => part && part !== '.' && part !== '..');
}

function loadYamlMapping(filePath, label) {
  let document;
  try {
    document = yaml.load(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`${label}_LOAD_FAILED: ${error.message}`);
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error(`${label}_INVALID: expected a YAML mapping`);
  }
  return document;
}

function validateHarnessConfig(config) {
  const phases = config.exec?.service_phases;
  if (!phases || typeof phases !== 'object' || Array.isArray(phases)) {
    throw new Error('HARNESS_CONFIG_INVALID: exec.service_phases is required');
  }
  for (const [mode, plan] of Object.entries(phases)) {
    if (!Array.isArray(plan) || plan.length === 0 || plan.some((phase) =>
      typeof phase !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(phase)
    )) {
      throw new Error(`HARNESS_CONFIG_INVALID: service phase plan ${mode} must be a non-empty string array`);
    }
    if (new Set(plan).size !== plan.length) {
      throw new Error(`HARNESS_CONFIG_INVALID: service phase plan ${mode} contains duplicates`);
    }
  }
  if (!Number.isFinite(config.ab_test?.quality_threshold) || config.ab_test.quality_threshold < 0) {
    throw new Error('HARNESS_CONFIG_INVALID: ab_test.quality_threshold must be a non-negative number');
  }
  if (!config.eval?.datasets_dir || !config.eval?.reports_dir) {
    throw new Error('HARNESS_CONFIG_INVALID: eval datasets_dir and reports_dir are required');
  }
  for (const [name, value] of [
    ['eval.datasets_dir', config.eval.datasets_dir],
    ['eval.reports_dir', config.eval.reports_dir],
    ['exec.checkpoint_subdir', config.exec?.checkpoint_subdir],
  ]) {
    if (!isSafeRelativeConfigPath(value)) {
      throw new Error(`HARNESS_CONFIG_INVALID: ${name} must be a contained relative path`);
    }
  }
  if (!Number.isInteger(config.behavior?.adapter_timeout_ms) || config.behavior.adapter_timeout_ms <= 0 ||
      !Number.isInteger(config.behavior?.minimum_long_context_tokens) || config.behavior.minimum_long_context_tokens <= 0) {
    throw new Error('HARNESS_CONFIG_INVALID: behavior timeout and long-context minimum must be positive integers');
  }
  return config;
}

function loadHarnessConfig({ fresh = false, filePath = CONFIG_PATH } = {}) {
  if (!fresh && filePath === CONFIG_PATH && configCache) return configCache;
  const config = validateHarnessConfig(loadYamlMapping(filePath, 'HARNESS_CONFIG'));
  if (filePath === CONFIG_PATH) configCache = config;
  return config;
}

function resolveHarnessPath(relativePath) {
  const resolved = path.resolve(HARNESS_ROOT, relativePath);
  const rel = path.relative(HARNESS_ROOT, resolved);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`HARNESS_CONFIG_PATH_ESCAPE: ${relativePath}`);
  }
  return resolved;
}

function getServicePhases(mode) {
  const phases = loadHarnessConfig().exec.service_phases[mode];
  if (!phases) {
    const valid = Object.keys(loadHarnessConfig().exec.service_phases).sort().join(', ');
    throw new Error(`Unknown service mode "${mode}" — valid modes: ${valid}`);
  }
  return [...phases];
}

module.exports = {
  CONFIG_PATH,
  HARNESS_ROOT,
  getServicePhases,
  loadHarnessConfig,
  loadYamlMapping,
  resolveHarnessPath,
};
