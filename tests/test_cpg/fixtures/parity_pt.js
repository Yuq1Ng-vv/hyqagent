/** Cross-language path traversal fixture — JavaScript (Node.js). */

var fs = require('fs');

function readFile() {
    var filename = process.env.FILE_PATH;  // $ source=path_traversal
    return fs.readFileSync(filename, 'utf8');  // $ sink=path_traversal
}

function serveStatic() {
    var p = '/tmp/' + (process.env.USER_FILE || '');  // $ source=path_traversal
    return fs.readFile(p, 'utf8');  // $ sink=path_traversal
}
