const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host || '127.0.0.1';
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        if (err) return res.status(500).send('Ping failed');
        res.send(stdout);
    });
});

app.get('/backup', (req, res) => {
    const filename = req.query.file || 'default';
    exec(
        `tar -czf /backups/${filename}.tar.gz /data/${filename}`,
        (err, stdout) => {
            if (err) return res.status(500).send('Backup failed');
            res.send('Backup complete');
        }
    );
});

app.listen(3000);