/** Cross-language SSRF fixture — JavaScript (Node.js). */

var http = require('http');

function proxy(req, res) {
    var url = req.query.url;  // $ source=ssrf
    http.get(url, function(resp) {  // $ sink=ssrf
        resp.pipe(res);
    });
}

function fetchUrl(req, res) {
    var target = req.query.target;  // $ source=ssrf
    var options = { hostname: target, path: '/api/data', method: 'GET' };
    var innerReq = http.request(options, function(innerResp) {  // $ sink=ssrf
        innerResp.pipe(res);
    });
    innerReq.end();
}
