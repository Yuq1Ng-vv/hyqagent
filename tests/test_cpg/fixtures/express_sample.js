// Express test fixture for framework extractor tests.

const express = require('express');
const app = express();

const auth = (req, res, next) => {
    if (req.headers.authorization) next();
    else res.status(401).send('Unauthorized');
};

app.get('/', (req, res) => {
    res.send('Hello');
});

app.get('/users', function listUsers(req, res) {
    const page = req.query.page || 1;
    res.send(`Users page ${page}`);
});

app.post('/users/:id', auth, (req, res) => {
    const name = req.body.name;
    res.json({ id: req.params.id, name });
});

app.get('/admin/stats', auth, function adminStats(req, res) {
    res.json({ status: 'ok' });
});
