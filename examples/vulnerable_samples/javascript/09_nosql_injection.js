const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());

let db;
MongoClient.connect('mongodb://localhost/app').then(client => {
    db = client.db();
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.collection('users').findOne({
        username: username,
        password: password,
    });
    if (user) {
        res.json({ token: 'session-token', userId: user._id });
    } else {
        res.status(401).send('invalid credentials');
    }
});

app.get('/users/search', async (req, res) => {
    const name = req.query.name;
    const users = await db.collection('users').find({ name: name }).toArray();
    res.json(users);
});

app.listen(3000);