const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).send('url required');
    try {
        const response = await axios.get(url, { timeout: 5000 });
        res.send(response.data);
    } catch (err) {
        res.status(500).send('fetch failed');
    }
});

app.post('/webhook-proxy', async (req, res) => {
    const { target_url, payload } = req.body;
    try {
        await axios.post(target_url, payload, { timeout: 10000 });
        res.json({ status: 'sent' });
    } catch (err) {
        res.status(500).send('proxy failed');
    }
});

app.listen(3000);