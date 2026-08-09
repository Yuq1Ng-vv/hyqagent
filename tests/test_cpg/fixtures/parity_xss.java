/** Cross-language XSS fixture — Java (Spring). */

import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class XssController {

    @GetMapping("/hello")
    public void hello(@RequestParam("name") String name,  // $ source=xss
                       HttpServletResponse response) throws IOException {
        response.getWriter().write("<h1>Hello " + name + "</h1>");  // $ sink=xss
    }

    @GetMapping("/reflect")
    public void reflect(@RequestParam("msg") String msg,  // $ source=xss
                        HttpServletResponse response) throws IOException {
        response.getWriter().write("<div>" + msg + "</div>");  // $ sink=xss
    }
}
