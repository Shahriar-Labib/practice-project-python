
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SafeQuery {
    public void findUser(Connection connection, String username)
            throws SQLException {

        String sql = "SELECT * FROM users WHERE username = ?";

        try (PreparedStatement statement =
                     connection.prepareStatement(sql)) {
            statement.setString(1, username);

            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    System.out.println(result.getString("username"));
                }
            }
        }
    }
}
