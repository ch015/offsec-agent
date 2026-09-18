const express = require('express');
const { db } = require('./mongo');

const app = express();

// NoSQL injection: user-controlled object reaches a Mongo selector.
app.post('/api/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password,
  });
  res.json(user);
});

module.exports = app;
