/** Cross-language crypto weakness fixture — Java. */

import java.security.MessageDigest;
import org.springframework.web.bind.annotation.*;

@RestController
public class CryptoController {

    @PostMapping("/register")
    public String register(@RequestParam("password") String password) throws Exception {  // $ source=crypto_weakness
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());  // $ sink=crypto_weakness
        return "Hash: " + new String(digest);
    }

    @GetMapping("/hash")
    public String hash(@RequestParam("data") String data) throws Exception {  // $ source=crypto_weakness
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(data.getBytes());  // $ sink=crypto_weakness
        return new String(digest);
    }
}
