/** Cross-language XSS fixture — JavaScript (Express). */

var req = { query: {} };
var res = { send: function() {} };

function helloHandler() {
    var name = req.query.name;  // $ source=xss
    res.send('<h1>Hello ' + name + '</h1>');  // $ sink=xss
}

function reflectHandler() {
    var msg = req.query.msg;  // $ source=xss
    res.send('<div>' + msg + '</div>');  // $ sink=xss
}
