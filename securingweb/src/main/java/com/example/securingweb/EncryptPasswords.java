package com.example.securingweb;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class EncryptPasswords {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/securingweb";
        String user = "root"; // username database
        String password = "root"; // password database

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            String selectQuery = "SELECT id, password FROM users";
            String updateQuery = "UPDATE users SET password = ? WHERE id = ?";

            try (PreparedStatement selectStmt = conn.prepareStatement(selectQuery);
                    PreparedStatement updateStmt = conn.prepareStatement(updateQuery);
                    ResultSet rs = selectStmt.executeQuery()) {

                while (rs.next()) {
                    int userId = rs.getInt("id");
                    String rawPassword = rs.getString("password");

                    // Kiểm tra nếu mật khẩu đã được mã hóa chưa
                    if (!rawPassword.startsWith("$2a$")) {
                        String hashedPassword = encoder.encode(rawPassword);

                        updateStmt.setString(1, hashedPassword);
                        updateStmt.setInt(2, userId);
                        updateStmt.executeUpdate();

                        System.out.println("Encrypted password for user ID: " + userId);
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
