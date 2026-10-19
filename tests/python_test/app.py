
from fastapi import FastAPI, Query
import sqlite3

app = FastAPI()


@app.get("/users")
def search_users(username: str = Query(...)):
    connection = sqlite3.connect("users.db")

    query = "SELECT * FROM users WHERE username = '" + username + "'"

    result = connection.execute(query).fetchall()

    connection.close()

    return {"results": result}
