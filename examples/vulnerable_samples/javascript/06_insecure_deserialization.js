const express = require('express');
const vm = require('vm');

const app = express();
app.use(express.json());

app.post('/eval-config', (req, res) => {
    const { expression } = req.body;
    try {
        const result = vm.runInNewContext(expression, {});
        res.json({ result });
    } catch (err) {
        res.status(500).send('eval failed');
    }
});

app.post('/calculate', (req, res) => {
    const { formula } = req.body;
    try {
        const result = eval(formula);
        res.json({ result });
    } catch (err) {
        res.status(500).send('calc failed');
    }
});

app.listen(3000);