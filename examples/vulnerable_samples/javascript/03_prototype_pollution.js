const express = require('express');
const app = express();
app.use(express.json());

function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

const userConfig = {};

app.post('/config/update', (req, res) => {
    merge(userConfig, req.body);
    res.json({ status: 'updated' });
});

app.get('/check-admin', (req, res) => {
    const user = {};
    if (user.isAdmin) {
        res.send('admin access granted');
    } else {
        res.send('regular user');
    }
});

app.listen(3000);