/* Sample JavaScript file for call-graph testing.

   Exercises: simple calls, method calls, chains, recursion, unresolved calls,
   arrow functions, and async functions.
*/

// ── Module-level functions ─────────────────────────────────────────────

function helper(x) {
    return x * 2;
}

function compute(a, b) {
    const result = helper(a);      // resolved
    console.log(`debug: ${result}`); // console.log → unresolved
    return helper(b) + result;      // resolved
}

function recursiveFib(n) {
    if (n <= 1) {
        return n;
    }
    return recursiveFib(n - 1) + recursiveFib(n - 2);  // self-loop
}

function callsExternal() {
    const data = fs.readFileSync("/tmp/file.txt");  // fs.readFileSync → unresolved
    console.log(data.toString());                   // console.log → unresolved
}

function noCalls(x) {
    return x + 1;
}

// ── Class with method calls ─────────────────────────────────────────────

class DataService {
    constructor(dbUrl) {
        this.dbUrl = dbUrl;
    }

    connect() {
        return !!this.dbUrl;
    }

    query(sql) {
        if (!this.connect()) {               // resolved: self.connect → connect
            return null;
        }
        return this.db.execute(sql);         // unresolved: external
    }

    batchQuery(sqls) {
        const results = [];
        for (const sql of sqls) {
            const result = this.query(sql);  // resolved: self.query → query
            if (result !== null) {
                results.push(result);
            }
        }
        return results;
    }

    fallback() {
        return fetchFromCache("users");      // unresolved: bare call
    }
}

// ── Async function ──────────────────────────────────────────────────────

async function asyncRunner(task) {
    const data = await helper(task);         // resolved
    return data;
}

// ── Arrow functions ─────────────────────────────────────────────────────

const arrowHandler = (req, res) => {
    const users = db.query("SELECT * FROM users");  // db.query → unresolved
    return res.json(users);                          // res.json → unresolved
};

// Arrow assigned to const — calls should be attributed to <arrow> or
// the enclosing scope (module-level in this case).  Our implementation
// skips calls inside anonymous arrow functions at module level.

// ── Nested functions ────────────────────────────────────────────────────

function outer(x) {
    function inner(y) {
        const val = helper(y);               // resolved: inner → helper
        console.log(val);                    // unresolved
        return val + 1;
    }

    const base = helper(x);                  // resolved: outer → helper
    return inner(base);                      // call to inner — resolved if name matches
}
