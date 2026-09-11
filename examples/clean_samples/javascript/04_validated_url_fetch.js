const express = require('express');
const axios = require('axios');
const { URL } = require('url');

const app = express();

const ALLOWED_HOSTS = new Set([
    'api.partner1.com',
    'api.partner2.com',
    'webhooks.example.com',
]);

function isSafeUrl(urlString) {
    let parsed;
    try {
        parsed = new URL(urlString);
    } catch {
        return false;
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    if (!ALLOWED_HOSTS.has(parsed.hostname)) return false;
    if (
        parsed.hostname.startsWith('10.') ||
        parsed.hostname.startsWith('172.16.') ||
        parsed.hostname.startsWith('192.168.') ||
        parsed.hostname === 'localhost' ||
        parsed.hostname === '127.0.0.1' ||
        parsed.hostname === '169.254.169.254'
    ) {
        return false;
    }
    return true;
}

app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    if (!isSafeUrl(url)) {
        return res.status(400).send('URL not allowed');
    }
    try {
        const response = await axios.get(url, { timeout: 5000 });
        res.send(response.data);
    } catch {
        res.status(500).send('fetch failed');
    }
});

app.listen(3000);