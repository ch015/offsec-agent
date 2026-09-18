const express = require('express');
const config = require('config');
const Redis = require('redis');

const app = express();
const cache = Redis.createClient();

// Real route — should be detected as an HTTP entry point.
app.get('/real', (req, res) => {
  // These are lookups, NOT routes — must not become entry points.
  const enabled = config.get('feature.enabled');
  cache.get('somekey');
  const m = new Map();
  m.get('k');
  res.json({ enabled });
});

module.exports = app;
