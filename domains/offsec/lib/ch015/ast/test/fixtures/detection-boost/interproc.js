const express = require('express');
const fs = require('fs');

const app = express();

// Interprocedural: tainted arg (req.params.file) → helper's parameter `f` → fs.readFile(f).
app.get('/download', (req, res) => {
  serveFile(req.params.file, res);
});

function serveFile(f, res) {
  const data = fs.readFile(f, 'utf8');
  res.send(data);
}

module.exports = app;
