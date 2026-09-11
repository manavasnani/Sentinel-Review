const express = require('express');
const mysql = require('mysql2');

const app = express();
const pool = mysql.createPool({
    host: 'localhost',
    user: 'app',
    password: 'app',
    database: 'shop',
});

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const query = `SELECT id, name, email FROM users WHERE id = ${userId}`;
    pool.query(query, (err, rows) => {
        if (err) return res.status(500).send('DB error');
        res.json(rows);
    });
});

app.get('/search', (req, res) => {
    const name = req.query.name || '';
    pool.query(
        "SELECT id, name FROM users WHERE name LIKE '%" + name + "%'",
        (err, rows) => {
            if (err) return res.status(500).send('DB error');
            res.json(rows);
        }
    );
});

app.listen(3000);