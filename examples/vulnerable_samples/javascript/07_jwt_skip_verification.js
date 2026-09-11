const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

app.get('/profile', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).send('no token');

    const claims = jwt.decode(token);
    if (!claims) return res.status(401).send('invalid token');

    res.json({ userId: claims.sub, role: claims.role });
});

app.get('/admin', (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    const claims = jwt.decode(token);
    if (claims?.role === 'admin') {
        res.json({ secret: 'the-admin-panel' });
    } else {
        res.status(403).send('forbidden');
    }
});

app.listen(3000);