
const sqlite3 = require("sqlite3").verbose();

function findUser(db, username) {
    const sql = "SELECT * FROM users WHERE username = ?";
    db.all(sql, [username], (error, rows) => {
        if (error) {
            console.error(error.message);
            return;
        }
        console.log(rows);
    });
}

module.exports = { findUser };
