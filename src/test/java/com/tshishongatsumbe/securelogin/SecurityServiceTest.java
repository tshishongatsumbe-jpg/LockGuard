package com.tshishongatsumbe.securelogin;

import org.junit.jupiter.api.*;
import java.io.File;
import static org.junit.jupiter.api.Assertions.*;

public class SecurityServiceTest {

    // A SEPARATE database file just for tests. This is the key fix:
    // if tests shared secure_login.db with the real app, leftover test
    // users from a previous run would cause tests like
    // "duplicateUsernameIsRejected" to fail on the SECOND run, because
    // the user would already exist from the FIRST run.
    private static final String TEST_DB_FILE = "test_secure_login.db";

    private Database db;
    private SecurityService security;

    // Runs before EVERY @Test method below. Deleting the file first
    // guarantees each test starts from a completely empty database —
    // no leftover users, no stale state, no flaky failures.
    @BeforeEach
    void setUp() {
        new File(TEST_DB_FILE).delete();
        db = new Database(TEST_DB_FILE);
        security = new SecurityService(db);
    }

    // Runs after EVERY @Test method. Closes the connection, then deletes
    // the test database again so nothing is left behind on disk.
    @AfterEach
    void tearDown() {
        db.close();
        new File(TEST_DB_FILE).delete();
    }

    // ---------- Password hashing tests ----------

    @Test
    void hashedPasswordIsNotPlainText() {
        String hash = security.hashPassword("MyStrongPass1!");
        assertNotEquals("MyStrongPass1!", hash); // the stored hash must never equal the raw password
    }

    @Test
    void correctPasswordVerifies() {
        String hash = security.hashPassword("MyStrongPass1!");
        assertTrue(security.checkPassword("MyStrongPass1!", hash));
    }

    @Test
    void wrongPasswordFailsVerification() {
        String hash = security.hashPassword("MyStrongPass1!");
        assertFalse(security.checkPassword("WrongPassword", hash));
    }

    // ---------- Password strength tests ----------

    @Test
    void shortPasswordIsWeak() {
        assertFalse(security.isPasswordStrong("abc123")); // under 8 characters
    }

    @Test
    void passwordWithNoSpecialCharIsWeak() {
        assertFalse(security.isPasswordStrong("Abcdefg1")); // missing a special character
    }

    @Test
    void strongPasswordPasses() {
        assertTrue(security.isPasswordStrong("Abcdef1!")); // has upper, lower, digit, special
    }

    // ---------- Username validation tests ----------

    @Test
    void emptyUsernameIsInvalid() {
        assertFalse(security.isValidUsername(""));
    }

    @Test
    void usernameWithSpacesIsInvalid() {
        assertFalse(security.isValidUsername("bad name"));
    }

    @Test
    void usernameTooShortIsInvalid() {
        assertFalse(security.isValidUsername("ab")); // under 3 characters
    }

    @Test
    void usernameWithSymbolsIsInvalid() {
        assertFalse(security.isValidUsername("bad@name")); // only letters/digits/underscore allowed
    }

    @Test
    void validUsernamePasses() {
        assertTrue(security.isValidUsername("valid_user123"));
    }

    // ---------- Lockout logic tests ----------

    @Test
    void accountLocksAfterFiveFailedAttempts() {
        String testUser = "test_lockout_user";
        User user = new User(testUser, security.hashPassword("CorrectPass1!"), "USER");
        db.saveUser(user);

        // Deliberately fail login 5 times to trigger the lockout threshold
        SecurityService.LoginResult result = null;
        for (int i = 0; i < 5; i++) {
            result = security.attemptLogin(testUser, "WrongPassword");
        }
        assertTrue(result.message.contains("locked"));

        // Even the CORRECT password should now be rejected, because the account is locked
        result = security.attemptLogin(testUser, "CorrectPass1!");
        assertFalse(result.success, "Correct password should still be rejected once locked");
    }

    @Test
    void unlockUserRestoresAccess() {
        String testUser = "test_unlock_user";
        User user = new User(testUser, security.hashPassword("CorrectPass1!"), "USER");
        db.saveUser(user);

        // Lock the account first (same as above)
        for (int i = 0; i < 5; i++) {
            security.attemptLogin(testUser, "WrongPassword");
        }
        assertTrue(db.findUserByUsername(testUser).isLocked());

        // Simulate an admin unlocking it
        assertTrue(security.unlockUser(testUser));
        assertFalse(db.findUserByUsername(testUser).isLocked());

        // Login should now succeed again with the correct password
        SecurityService.LoginResult result = security.attemptLogin(testUser, "CorrectPass1!");
        assertTrue(result.success);
    }

    // ---------- Database constraint test ----------

    @Test
    void duplicateUsernameIsRejected() {
        String testUser = "test_duplicate_user";
        User first = new User(testUser, "somehash", "USER");
        User second = new User(testUser, "otherhash", "USER"); // same username, different hash

        // First save succeeds because the database starts empty (thanks to @BeforeEach above)
        assertTrue(db.saveUser(first));
        // Second save fails because "username" has a UNIQUE constraint in schema.sql
        assertFalse(db.saveUser(second));
    }
}