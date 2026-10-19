const express = require("express");

const app = express();

app.get("/", (req, res) => {
    res.send("Express framework detection test");
});

module.exports = app;