package com.tshishongatsumbe.securelogin;

/**
 * Represents a user and stores their account information and login status.
 */
public class User {
    private int id;
    private String username;
    private String passwordHash;
    private String role;
    private int failedAttempts;
    private boolean locked;

    // Used when creating a brand-new user (before it has a DB id)
    public User(String username, String passwordHash, String role) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.failedAttempts = 0;
        this.locked = false;
    }

    // Used when loading an existing user from the database
    public User(int id, String username, String passwordHash, String role,
                int failedAttempts, boolean locked) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.failedAttempts = failedAttempts;
        this.locked = locked;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts) { this.failedAttempts = failedAttempts; }
    public void incrementFailedAttempts() { this.failedAttempts++; }
    public void resetFailedAttempts() { this.failedAttempts = 0; }

    public boolean isLocked() { return locked; }
    public void setLocked(boolean locked) { this.locked = locked; }

    public boolean isAdmin() { return "ADMIN".equalsIgnoreCase(role); }

    @Override
    public String toString() {
        return "User{id=" + id + ", username='" + username + "', role='" + role +
                "', failedAttempts=" + failedAttempts + ", locked=" + locked + "}";
    }
}
