const path = require('node:path');
const fs = require('node:fs');
const { repos } = require('./paths.cjs');
const { buildAstContext } = require(path.join(repos.code, 'lib/ch015/ast/context-builder.js'));
buildAstContext(path.join(__dirname, 'fixture'), {
  engagementDir: process.argv[2], semgrep: false,
}).then(result => {
  fs.writeFileSync(path.join(process.argv[2], 'ast-result.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify({ completed: result.ok, resultFile: path.join(process.argv[2], 'ast-result.json') }));
}).catch(error => { console.error(error.message); process.exitCode = 1; });
