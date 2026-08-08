/** Cross-language SQL injection fixture — JavaScript (Express). */

var req = { query: {}, body: {} };
var db = { query: function() {}, execute: function() {} };

function search() {
    var keyword = req.query.q;  // $ source=sql_injection
    db.query("SELECT * FROM posts WHERE title LIKE '%" + keyword + "%'");  // $ sink=sql_injection
}

function getUser() {
    var uid = req.query.uid;  // $ source=sql_injection
    db.execute("SELECT * FROM users WHERE id = " + uid);  // $ sink=sql_injection
}
