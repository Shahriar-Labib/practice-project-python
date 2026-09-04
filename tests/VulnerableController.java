package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
@RequestMapping("/users")
public class VulnerableController {

    @GetMapping("/search")
    public String search(@RequestParam String username) throws Exception {

        Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/test",
                "root",
                "password"
        );

        String query = "SELECT * FROM users WHERE username='" + username + "'";

        Statement statement = connection.createStatement();
        ResultSet result = statement.executeQuery(query);

        return "Search completed";
    }
}