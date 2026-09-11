const express = require('express');
const { execFile } = require('child_process');

const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host || '127.0.0.1';
    if (!/^[a-zA-Z0-9._-]{1,253}$/.test(host)) {
        return res.status(400).send('invalid host');
    }
    execFile('ping', ['-c', '1', host], (err, stdout) => {
        if (err) return res.status(500).send('ping failed');
        res.send(stdout);
    });
});

app.get('/hostname', (req, res) => {
    execFile('hostname', [], (err, stdout) => {
        if (err) return res.status(500).send('failed');
        res.send(stdout.trim());
    });
});

app.listen(3000);