// Spring Boot test fixture for framework extractor tests.

package com.example.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/")
    public String index() {
        return "Hello";
    }

    @GetMapping("/users")
    public String listUsers(@RequestParam(defaultValue = "1") int page) {
        return "Users page " + page;
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('USER')")
    public String getUser(@PathVariable int id, @RequestParam(required = false) String name) {
        return "User " + id;
    }

    @PostMapping("/users")
    public String createUser(@RequestBody String body) {
        return "Created";
    }

    @GetMapping("/admin/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminStats() {
        return "Stats";
    }
}
