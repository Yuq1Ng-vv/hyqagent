/** Cross-language SSRF fixture — Java. */

import java.net.*;
import java.io.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class SsrfController {

    @GetMapping("/proxy")
    public String proxy(@RequestParam("url") String url) throws Exception {  // $ source=ssrf
        URL target = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) target.openConnection();  // $ sink=ssrf
        return new String(conn.getInputStream().readAllBytes());
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam("host") String host) throws Exception {  // $ source=ssrf
        URL u = new URL("http://" + host + "/api/data");
        URLConnection conn = u.openConnection();  // $ sink=ssrf
        return new String(conn.getInputStream().readAllBytes());
    }
}
