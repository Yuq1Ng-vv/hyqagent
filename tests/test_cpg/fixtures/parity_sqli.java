/** Cross-language SQL injection fixture — Java (Spring). */

import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @GetMapping("/search")
    public String search(@RequestParam("q") String keyword) {  // $ source=sql_injection
        jdbcTemplate.query("SELECT * FROM posts WHERE title LIKE '%" + keyword + "%'");  // $ sink=sql_injection
        return "ok";
    }

    @GetMapping("/user")
    public String getUser(@RequestParam("uid") String uid) {  // $ source=sql_injection
        jdbcTemplate.queryForList("SELECT * FROM users WHERE id = " + uid);  // $ sink=sql_injection
        return "ok";
    }
}
