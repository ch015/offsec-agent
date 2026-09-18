const express = require('express');
const { getUser, createUser } = require('./db');
const { checkAuth } = require('./auth');

const app = express();
app.use(express.json());

app.get('/api/users/:id', checkAuth, async (req, res) => {
  const user = await getUser(req.params.id);
  res.json(user);
});

app.post('/api/users', async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const result = await createUser(name, email);
  res.json(result);
});

app.get('/api/search', async (req, res) => {
  const q = req.query.q;
  const results = await searchUsers(q);
  res.send(`<h1>Results for ${q}</h1>`);
});

module.exports = app;
