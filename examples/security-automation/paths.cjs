const fs = require('node:fs');
const path = require('node:path');

const exampleDir = __dirname;
const ownRepo = path.resolve(exampleDir, '../..');
let workspaceRoot = process.env.SECURITY_PROJECT_ROOT && path.resolve(process.env.SECURITY_PROJECT_ROOT);
for (let directory = exampleDir; !workspaceRoot;) {
  if (fs.existsSync(path.join(directory, 'agent/secops-agent-offsec/package.json'))) {
    workspaceRoot = directory;
    break;
  }
  const parent = path.dirname(directory);
  if (parent === directory) break;
  directory = parent;
}
workspaceRoot ||= path.resolve(ownRepo, '../..');
const configured = (name, fallback) => path.resolve(process.env[name] || fallback);
const repos = {
  offsec: configured('DEMO_OFFSEC_DIR', ownRepo),
  soc: configured('DEMO_SOC_DIR', path.join(workspaceRoot, 'agent/secops-agent-soc')),
  code: configured('DEMO_CODE_DIR', path.join(workspaceRoot, 'pentester/code-pentester')),
  web: configured('DEMO_WEB_DIR', path.join(workspaceRoot, 'pentester/web-pentester')),
};

module.exports = { exampleDir, workspaceRoot, repos };
