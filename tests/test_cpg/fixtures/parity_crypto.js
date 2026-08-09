/** Cross-language crypto weakness fixture — JavaScript (Node.js). */

var crypto = require('crypto');

function hashPassword(req, res) {
    var password = req.body.password;  // $ source=crypto_weakness
    var hash = crypto.createHash('md5').update(password).digest('hex');  // $ sink=crypto_weakness
    res.send('Hash: ' + hash);
}

function hashData(req, res) {
    var data = req.query.data;  // $ source=crypto_weakness
    var hash = crypto.createHash('sha1').update(data).digest('hex');  // $ sink=crypto_weakness
    res.send(hash);
}
