/** Cross-language command injection fixture — Java. */

public class AdminTool {

    public void pingHost() {
        String host = System.getProperty("user.host");  // $ source=command_injection
        Runtime.getRuntime().exec("ping -c 1 " + host);  // $ sink=command_injection
    }

    public void runAdminCmd() {
        String cmd = System.getenv("ADMIN_CMD");  // $ source=command_injection
        Runtime.getRuntime().exec(cmd);  // $ sink=command_injection
    }
}
