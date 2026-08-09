/** Cross-language open redirect fixture — JavaScript (Express). */

var req = { query: {}, body: {} };
var res = { redirect: function() {} };

function loginRedirect() {
    var next = req.query.next || '/';  // $ source=open_redirect
    res.redirect(next);  // $ sink=open_redirect
}

function gotoRedirect() {
    var target = req.query.url;  // $ source=open_redirect
    res.redirect(302, target);  // $ sink=open_redirect
}
