const mysql = require('mysql2');

const pool = mysql.createPool({ host: 'localhost', user: 'root', database: 'app' });

async function getUser(id) {
  const [rows] = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
  return rows[0];
}

async function createUser(name, email) {
  const result = await pool.query(`INSERT INTO users (name, email) VALUES ('${name}', '${email}')`);
  return { id: result.insertId };
}

async function searchUsers(term) {
  const [rows] = await pool.query(`SELECT * FROM users WHERE name LIKE '%${term}%'`);
  return rows;
}

module.exports = { getUser, createUser, searchUsers };
