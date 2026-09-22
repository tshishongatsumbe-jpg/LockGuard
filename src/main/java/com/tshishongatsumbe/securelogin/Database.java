package com.tshishongatsumbe.securelogin;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Responsible for communicating with the SQLite database.
 * Loads its schema from schema.sql (src/main/resources), and
 * saves/finds/updates users, plus logs and retrieves login
 * attempts for auditing.
 */
public class Database {
    private final String url;       // the JDBC connection string, e.g. "jdbc:sqlite:secure_login.db"
    private Connection connection;

    // Used by the real app (SecureLoginSystem) — always points at the live database file.
    public Database() {
        this("secure_login.db");
    }

    /** Used by tests — lets us pass in a DIFFERENT file name, so tests never
     * touch the real secure_login.db that the running app uses.
     */
    public Database(String dbFileName) {
        this.url = "jdbc:sqlite:" + dbFileName;
        connect();
        createTables();
    }

    public void connect() {
        try {
            connection = DriverManager.getConnection(url);
        } catch (SQLException e) {
            System.out.println("Database connection failed: " + e.getMessage());
        }
    }

    /** Reads schema.sql (the CREATE TABLE statements) and runs it against
    * whichever database file this instance is connected to. Because
    * "CREATE TABLE IF NOT EXISTS" is used in schema.sql, this is safe to
    * run every time the app starts — it won't wipe existing data.
    */
    public void createTables() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("schema.sql")) {
            if (is == null) {
                System.out.println("schema.sql not found on classpath.");
                return;
            }
            StringBuilder sql = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().startsWith("--") || line.trim().isEmpty()) continue; // skip comments/blank lines
                    sql.append(line).append("\n");
                }
            }
            // schema.sql can contain multiple statements separated by ";" — split and run each one
            String[] statements = sql.toString().split(";");
            try (Statement stmt = connection.createStatement()) {
                for (String statement : statements) {
                    if (!statement.trim().isEmpty()) {
                        stmt.execute(statement.trim());
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Could not create tables from schema.sql: " + e.getMessage());
        }
    }

    // ---------- Users ----------

    /**
    * Inserts a new user row. Uses PreparedStatement (not string concatenation)
    * so user input can never be interpreted as SQL — this is what defends against SQL injection.
    */
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
            // This fires when the UNIQUE constraint on "username" is violated —
            // i.e. someone tries to register a username that already exists.
            System.out.println("Could not save user: " + e.getMessage());
            return false;
        }
    }

    // Looks up a user by username. Returns null if not found.
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

    /** Saves changes to an existing user (e.g. after a failed login attempt,
    * or after locking/unlocking the account).
    */
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

    /** Records every login attempt (success or failure) — this is the audit trail
     * an admin can review later to see who tried to log in and when.
     */
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

    // Fetches the most recent login attempts for a given user (used by the admin menu).
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

    // Closes the database connection cleanly when the app (or a test) is done with it.
    public void close() {
        try {
            if (connection != null) connection.close();
        } catch (SQLException e) {
            System.out.println("Could not close connection: " + e.getMessage());
        }
    }
}