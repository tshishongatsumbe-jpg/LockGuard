package com.tshishongatsumbe.securelogin;

import org.mindrot.jbcrypt.BCrypt;

/**
 * Contains the security rules of the application: password hashing (BCrypt),
 * password strength checks, username validation, account lockout, and
 * login attempt auditing.
 */
public class SecurityService {
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int BCRYPT_ROUNDS = 12;

    private final Database database;

    public SecurityService(Database database) {
        this.database = database;
    }

    // ---------- Password hashing (BCrypt) ----------

    public String hashPassword(String plainPassword) {
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(BCRYPT_ROUNDS));
    }

    public boolean checkPassword(String plainPassword, String storedHash) {
        return BCrypt.checkpw(plainPassword, storedHash);
    }

    // ---------- Password strength ----------

    public boolean isPasswordStrong(String password) {
        if (password.length() < 8) return false;
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(c -> !Character.isLetterOrDigit(c));
        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    // ---------- Username validation ----------

    /**
     * Valid usernames: 3-20 characters, letters/digits/underscore only,
     * no leading/trailing whitespace, not empty.
     */
    public boolean isValidUsername(String username) {
        if (username == null) return false;
        String trimmed = username.trim();
        if (trimmed.isEmpty() || trimmed.length() < 3 || trimmed.length() > 20) return false;
        return trimmed.matches("^[a-zA-Z0-9_]+$");
    }

    // ---------- Login / lockout logic ----------

    public LoginResult attemptLogin(String username, String plainPassword) {
        User user = database.findUserByUsername(username);

        if (user == null) {
            database.logAttempt(username, false);
            return new LoginResult(false, "No account found for that username.", null);
        }

        if (user.isLocked()) {
            database.logAttempt(username, false);
            return new LoginResult(false, "Account locked! Too many failed login attempts.", user);
        }

        if (checkPassword(plainPassword, user.getPasswordHash())) {
            user.resetFailedAttempts();
            database.updateUser(user);
            database.logAttempt(username, true);
            return new LoginResult(true, "Login successful! Welcome " + user.getUsername() + ".", user);
        }

        user.incrementFailedAttempts();
        if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setLocked(true);
            database.updateUser(user);
            database.logAttempt(username, false);
            return new LoginResult(false, "Account locked! Too many failed login attempts.", user);
        }

        database.updateUser(user);
        database.logAttempt(username, false);
        int remaining = MAX_FAILED_ATTEMPTS - user.getFailedAttempts();
        return new LoginResult(false, "Incorrect password. Attempts remaining: " + remaining, user);
    }

    public boolean unlockUser(String username) {
        User user = database.findUserByUsername(username);
        if (user == null) return false;
        user.setLocked(false);
        user.resetFailedAttempts();
        return database.updateUser(user);
    }

    // ---------- Result holder ----------

    public static class LoginResult {
        public final boolean success;
        public final String message;
        public final User user;

        public LoginResult(boolean success, String message, User user) {
            this.success = success;
            this.message = message;
            this.user = user;
        }
    }
}