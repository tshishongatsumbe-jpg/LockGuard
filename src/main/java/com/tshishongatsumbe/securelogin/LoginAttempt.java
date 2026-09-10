package com.tshishongatsumbe.securelogin;
import java.time.LocalDateTime;
/**
 * Represents a single row in the
 login_attempts audit log.
 */
public class LoginAttempt {
    private int id;
    private String username;
    private LocalDateTime timestamp;
    private boolean success;
    public LoginAttempt(int id, String
            username, LocalDateTime timestamp, boolean
                                success) {
        this.id = id;
        this.username = username;
        this.timestamp = timestamp;
        this.success = success;
    }
    public int getId() { return id; }
    public String getUsername() { return
            username; }
    public LocalDateTime getTimestamp() {
        return timestamp; }
    public boolean isSuccess() { return
            success; }

    @Override
    public String toString() {
        return "[" + timestamp + "] " +
                username + " - " + (success ? "SUCCESS" :
                "FAILED");
    }
}