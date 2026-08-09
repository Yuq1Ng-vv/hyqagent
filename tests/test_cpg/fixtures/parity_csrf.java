/** Cross-language CSRF fixture — Java (Spring Security).

Spring Security configuration with CSRF protection explicitly disabled.
Detected by config_issues rules (http.csrf().disable() pattern).
*/

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()  // $ VULNERABLE: CSRF disabled globally
            .authorizeRequests()
            .anyRequest().permitAll();
    }
}
