const express = require('express');
const axios = require('axios');
const http = require('http');

const app = express();

// SSRF: user-controlled URL flows directly into a server-side HTTP client.
app.get('/api/fetch', async (req, res) => {
  const target = req.query.url;
  const resp = await axios.get(target);
  res.send(resp.data);
});

// SSRF via node http.get with a user-controlled host.
app.get('/api/proxy', (req, res) => {
  const host = req.query.host;
  http.get(host, (r) => r.pipe(res));
});

module.exports = app;
