
const express = require("express");
const sqlite3 = require("sqlite3").verbose();

const app = express();

app.get("/users", (req, res) => {
    const username = req.query.username;

    const query =
        "SELECT * FROM users WHERE username = '" + username + "'";

    const db = new sqlite3.Database("users.db");

    db.all(query, (error, rows) => {
        if (error) {
            return res.status(500).send("Database error");
        }

        res.json(rows);
        db.close();
    });
});

module.exports = app;
