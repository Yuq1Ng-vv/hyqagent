/** Cross-language path traversal fixture — Java. */

import java.io.FileInputStream;

public class FileService {

    public void readFile() {
        String filename = System.getenv("FILE_PATH");  // $ source=path_traversal
        new FileInputStream(filename);  // $ sink=path_traversal
    }

    public void serveStatic() {
        String p = "/tmp/" + System.getenv("USER_FILE");  // $ source=path_traversal
        new FileInputStream(p);  // $ sink=path_traversal
    }
}
