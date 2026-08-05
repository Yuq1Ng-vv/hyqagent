/* Sample Java file for call-graph testing.

   Exercises: simple calls, method calls, chains, recursion, unresolved calls.
   Note: Java doesn't have module-level functions — all methods are in a class.
*/

import java.util.List;
import java.util.ArrayList;

// ── Helper class ────────────────────────────────────────────────────────

class Utils {
    public static int helper(int x) {
        return x * 2;
    }

    public static void log(String msg) {
        System.out.println(msg);  // System.out.println → unresolved (println)
    }
}

// ── Main service class ──────────────────────────────────────────────────

public class UserService {

    private Database db;

    public UserService(Database db) {
        this.db = db;
    }

    // ── Simple methods ────────────────────────────────────────────

    public int compute(int a, int b) {
        int result = Utils.helper(a);          // Utils.helper → unresolved locally
        System.out.println("debug: " + result); // println → unresolved
        return Utils.helper(b) + result;
    }

    public int recursiveFib(int n) {
        if (n <= 1) {
            return n;
        }
        return recursiveFib(n - 1) + recursiveFib(n - 2);  // self-loop
    }

    public int noCalls(int x) {
        return x + 1;
    }

    // ── Method chaining ───────────────────────────────────────────

    public String getUser(int userId) {
        String query = "SELECT * FROM users WHERE id=" + userId;
        return this.db.execute(query);         // this.db.execute → execute, unresolved
    }

    public List<String> listUsers(int limit) {
        String query = "SELECT name FROM users LIMIT " + limit;
        return this.db.executeQuery(query);    // executeQuery, unresolved
    }

    public void process() {
        String user = this.getUser(1);         // this.getUser → getUser, resolved
        this.validate(user);                   // this.validate → validate, resolved
        System.out.println("done");            // println, unresolved
    }

    public void validate(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Invalid input");
        }
    }

    // ── Chain with local calls ────────────────────────────────────

    public void runPipeline() {
        this.stepOne();                        // resolved
    }

    public void stepOne() {
        this.stepTwo();                        // resolved
    }

    public void stepTwo() {
        Utils.log("completed");                // Utils.log → unresolved (log)
    }
}

// ── Mock database class ─────────────────────────────────────────────────

class Database {
    public String execute(String sql) {
        return "result";
    }

    public List<String> executeQuery(String sql) {
        return new ArrayList<>();
    }
}
