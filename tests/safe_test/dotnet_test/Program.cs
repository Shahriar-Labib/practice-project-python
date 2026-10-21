
using Microsoft.Data.SqlClient;

public class SafeQuery
{
    public static void FindUser(SqlConnection connection, string username)
    {
        const string sql =
            "SELECT * FROM users WHERE username = @username";

        using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@username", username);

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            Console.WriteLine(reader["username"]);
        }
    }
}
