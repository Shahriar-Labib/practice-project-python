import sqlite3

def find_user(connection: sqlite3.Connection, username: str):
    sql = "SELECT * FROM users WHERE username = ?"
    return connection.execute(sql, (username,)).fetchall()