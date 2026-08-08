/** Cross-language command injection fixture — JavaScript (Node.js). */

var cp = require('child_process');

function pingHost() {
    var host = process.argv[2];  // $ source=command_injection
    cp.exec("ping -c 1 " + host);  // $ sink=command_injection
}

function runAdminCmd() {
    var cmd = process.env.ADMIN_CMD;  // $ source=command_injection
    cp.exec(cmd);  // $ sink=command_injection
}
