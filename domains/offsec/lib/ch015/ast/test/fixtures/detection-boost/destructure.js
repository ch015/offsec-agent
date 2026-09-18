const express = require('express');
const fs = require('fs');

const app = express();

// Path traversal via destructured source: const { file } = req.query → fs.readFile(file)
app.get('/api/read', (req, res) => {
  const { file } = req.query;
  const data = fs.readFile(file, 'utf8');
  res.send(data);
});

module.exports = app;
