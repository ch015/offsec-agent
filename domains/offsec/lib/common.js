'use strict';

/**
 * Common 모듈 — 단일 진입점
 * 모든 lib 모듈을 re-export
 */
module.exports = {
  // === core ===
  get PLUGIN_ROOT() { return require('./core/platform').PLUGIN_ROOT; },
  get PROJECT_DIR() { return require('./core/platform').PROJECT_DIR; },
  get IS_PLUGIN() { return require('./core/platform').IS_PLUGIN; },
  get PLUGIN_NAME() { return require('./core/platform').PLUGIN_NAME; },
  get getPluginPath() { return require('./core/platform').getPluginPath; },
  get getProjectPath() { return require('./core/platform').getProjectPath; },
  get getTemplatePath() { return require('./core/platform').getTemplatePath; },
  get getSkillPath() { return require('./core/platform').getSkillPath; },
  get getCommandPath() { return require('./core/platform').getCommandPath; },

  get loadConfig() { return require('./core/config').loadConfig; },
  get getConfig() { return require('./core/config').getConfig; },
  get safeJsonParse() { return require('./core/config').safeJsonParse; },
  get detectProjectLevel() { return require('./core/config').detectProjectLevel; },

  get readStdin() { return require('./core/io').readStdin; },
  get parseHookInput() { return require('./core/io').parseHookInput; },
  get outputAllow() { return require('./core/io').outputAllow; },
  get outputBlock() { return require('./core/io').outputBlock; },
  get outputContext() { return require('./core/io').outputContext; },
  get outputJson() { return require('./core/io').outputJson; },
  get logToStderr() { return require('./core/io').logToStderr; },

  // === ch015 ===
  get calculateSecurityScore() { return require('./ch015/scoring').calculateSecurityScore; },
  get getSeverityWeight() { return require('./ch015/scoring').getSeverityWeight; },
  get formatScore() { return require('./ch015/scoring').formatScore; },
  get isPassingScore() { return require('./ch015/scoring').isPassingScore; },

  get createFinding() { return require('./ch015/finding').createFinding; },
  get formatFindingId() { return require('./ch015/finding').formatFindingId; },
  get sortFindings() { return require('./ch015/finding').sortFindings; },
  get groupByCategory() { return require('./ch015/finding').groupByCategory; },
  get groupBySeverity() { return require('./ch015/finding').groupBySeverity; },
  get groupByDimension() { return require('./ch015/finding').groupByDimension; },
  get groupByRootCause() { return require('./ch015/finding').groupByRootCause; },

  // === recon cache ===
  get loadReconCache() { return require('./ch015/recon-cache').loadReconCache; },
  get saveReconCache() { return require('./ch015/recon-cache').saveReconCache; },
  get invalidateReconCache() { return require('./ch015/recon-cache').invalidateCache; },
  get listReconCache() { return require('./ch015/recon-cache').listCache; },
  get pruneReconCache() { return require('./ch015/recon-cache').pruneExpired; }
};
