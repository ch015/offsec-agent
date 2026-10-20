'use strict';

const path = require('path');
const fs = require('fs');

// 플러그인 루트 디렉토리 결정
const PLUGIN_ROOT = process.env.CLAUDE_PLUGIN_ROOT || path.resolve(__dirname, '../..');
const PROJECT_DIR = process.env.PROJECT_DIR || process.cwd();
const IS_PLUGIN = !!process.env.CLAUDE_PLUGIN_ROOT;
const PLUGIN_NAME = 'ch015';

/**
 * 플러그인 내부 경로 반환
 */
function getPluginPath(...segments) {
  return path.join(PLUGIN_ROOT, ...segments);
}

/**
 * 프로젝트(분석 대상) 내부 경로 반환
 */
function getProjectPath(...segments) {
  return path.join(PROJECT_DIR, ...segments);
}

/**
 * 스킬 경로 반환
 */
function getSkillPath(service, skillName) {
  return getPluginPath('skills', PLUGIN_NAME, service, skillName);
}

module.exports = {
  PLUGIN_ROOT,
  PROJECT_DIR,
  IS_PLUGIN,
  PLUGIN_NAME,
  getPluginPath,
  getProjectPath,
  getSkillPath
};
