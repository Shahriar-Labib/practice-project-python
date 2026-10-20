
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/users", (string username) =>
{
    using var connection = new SqliteConnection("Data Source=users.db");
    connection.Open();

    var query =
        "SELECT * FROM users WHERE username = '" + username + "'";

    using var command = connection.CreateCommand();
    command.CommandText = query;

    using var reader = command.ExecuteReader();

    return Results.Ok("Query executed");
});

app.Run();
