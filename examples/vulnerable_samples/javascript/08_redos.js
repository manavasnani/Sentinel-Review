const express = require('express');
const app = express();
app.use(express.json());

const EMAIL_REGEX = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.[a-zA-Z]{2,}$/;

app.post('/validate-email', (req, res) => {
    const { email } = req.body;
    const valid = EMAIL_REGEX.test(email);
    res.json({ valid });
});

const URL_REGEX = /^(https?:\/\/)?([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}(\/.*)?$/;

app.post('/validate-url', (req, res) => {
    const { url } = req.body;
    const valid = URL_REGEX.test(url);
    res.json({ valid });
});

app.listen(3000);