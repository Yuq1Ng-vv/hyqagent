// Sample Java file for parser testing
import java.util.List;
import java.util.ArrayList;
import java.sql.Connection;

public class UserService extends BaseService implements IUserRepo {

    private Connection db;

    public UserService(Connection db) {
        this.db = db;
    }

    public String getUser(int userId) {
        String query = "SELECT * FROM users WHERE id=" + userId;
        return db.execute(query);
    }

    public List<String> listUsers(int limit) {
        String query = "SELECT name FROM users LIMIT " + limit;
        return db.executeQuery(query);
    }

    private void validate(String input) throws Exception {
        if (input == null) {
            throw new Exception("Invalid input");
        }
    }
}
