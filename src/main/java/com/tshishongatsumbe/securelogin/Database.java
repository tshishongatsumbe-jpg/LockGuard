package com.tshishongatsumbe.securelogin;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Responsible for communicating with the SQLite database.
 * Connects, creates tables, and saves/finds/updates users,
 * plus logs and retrieves login attempts for auditing.
 */
public class Database {
    private static final String URL = "jdbc:sqlite:secure_login.db";
    private Connection connection;

    public Database() {
        connect();
        createTables();
    }

    public void connect() {
        try {
            connection = DriverManager.getConnection(URL);
        } catch (SQLException e) {
            System.out.println("Database connection failed: " + e.getMessage());
        }
    }

    public void createTables() {
        String users = "CREATE TABLE IF NOT EXISTS users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "username TEXT UNIQUE NOT NULL," +
                "password_hash TEXT NOT NULL," +
                "failed_attempts INTEGER DEFAULT 0," +
                "locked INTEGER DEFAULT 0," +
                "role TEXT DEFAULT 'USER'," +
                "two_factor_secret TEXT," +
                "two_factor_enabled INTEGER DEFAULT 0" +
                ")";

        String attempts = "CREATE TABLE IF NOT EXISTS login_attempts (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "username TEXT NOT NULL," +
                "timestamp TEXT NOT NULL," +
                "success INTEGER NOT NULL" +
                ")";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(users);
            stmt.execute(attempts);
        } catch (SQLException e) {
            System.out.println("Could not create tables: " + e.getMessage());
        }
    }

    // ---------- Users ----------

    public boolean saveUser(User user) {
        String sql = "INSERT INTO users (username, password_hash, failed_attempts, locked, role, " +
                "two_factor_secret, two_factor_enabled) VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, user.getUsername());
            ps.setString(2, user.getPasswordHash());
            ps.setInt(3, user.getFailedAttempts());
            ps.setInt(4, user.isLocked() ? 1 : 0);
            ps.setString(5, user.getRole());
            ps.setString(6, user.getTwoFactorSecret());
            ps.setInt(7, user.isTwoFactorEnabled() ? 1 : 0);
            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.out.println("Could not save user: " + e.getMessage());
            return false;
        }
    }

    public User findUserByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new User(
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getString("password_hash"),
                            rs.getString("role"),
                            rs.getInt("failed_attempts"),
                            rs.getInt("locked") == 1,
                            rs.getString("two_factor_secret"),
                            rs.getInt("two_factor_enabled") == 1
                    );
                }
            }
        } catch (SQLException e) {
            System.out.println("Could not find user: " + e.getMessage());
        }
        return null;
    }

    public boolean updateUser(User user) {
        String sql = "UPDATE users SET password_hash = ?, failed_attempts = ?, locked = ?, role = ?, " +
                "two_factor_secret = ?, two_factor_enabled = ? WHERE id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, user.getPasswordHash());
            ps.setInt(2, user.getFailedAttempts());
            ps.setInt(3, user.isLocked() ? 1 : 0);
            ps.setString(4, user.getRole());
            ps.setString(5, user.getTwoFactorSecret());
            ps.setInt(6, user.isTwoFactorEnabled() ? 1 : 0);
            ps.setInt(7, user.getId());
            ps.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.out.println("Could not update user: " + e.getMessage());
            return false;
        }
    }

    // ---------- Login attempt audit log ----------

    public void logAttempt(String username, boolean success) {
        String sql = "INSERT INTO login_attempts (username, timestamp, success) VALUES (?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, LocalDateTime.now().toString());
            ps.setInt(3, success ? 1 : 0);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.out.println("Could not log attempt: " + e.getMessage());
        }
    }

    public List<LoginAttempt> getRecentAttempts(String username, int limit) {
        List<LoginAttempt> results = new ArrayList<>();
        String sql = "SELECT * FROM login_attempts WHERE username = ? ORDER BY id DESC LIMIT ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setInt(2, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(new LoginAttempt(
                            rs.getInt("id"),
                            rs.getString("username"),
                            LocalDateTime.parse(rs.getString("timestamp")),
                            rs.getInt("success") == 1
                    ));
                }
            }
        } catch (SQLException e) {
            System.out.println("Could not fetch attempts: " + e.getMessage());
        }
        return results;
    }

    public void close() {
        try {
            if (connection != null) connection.close();
        } catch (SQLException e) {
            System.out.println("Could not close connection: " + e.getMessage());
        }
    }
}