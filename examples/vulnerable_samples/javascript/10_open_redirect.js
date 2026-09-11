const express = require('express');
const app = express();

app.get('/login', (req, res) => {
    const next = req.query.next || '/';
    res.redirect(next);
});

app.get('/logout', (req, res) => {
    const returnTo = req.query.return_to || '/';
    res.redirect(returnTo);
});

app.get('/auth/callback', (req, res) => {
    const { code, state, redirect_uri } = req.query;
    res.redirect(redirect_uri);
});

app.listen(3000);