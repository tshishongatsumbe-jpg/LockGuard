package com.tshishongatsumbe.securelogin;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

public class SecurityServiceTest {

    private Database db;
    private SecurityService security;

    @BeforeEach
    void setUp() {
        db = new Database();
        security = new SecurityService(db);
    }

    @AfterEach
    void tearDown() {
        db.close();
    }

    @Test
    void hashedPasswordIsNotPlainText() {
        String hash = security.hashPassword("MyStrongPass1!");
        assertNotEquals("MyStrongPass1!", hash);
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

    @Test
    void shortPasswordIsWeak() {
        assertFalse(security.isPasswordStrong("abc123"));
    }

    @Test
    void passwordWithNoSpecialCharIsWeak() {
        assertFalse(security.isPasswordStrong("Abcdefg1"));
    }

    @Test
    void strongPasswordPasses() {
        assertTrue(security.isPasswordStrong("Abcdef1!"));
    }

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
        assertFalse(security.isValidUsername("ab"));
    }

    @Test
    void usernameWithSymbolsIsInvalid() {
        assertFalse(security.isValidUsername("bad@name"));
    }

    @Test
    void validUsernamePasses() {
        assertTrue(security.isValidUsername("valid_user123"));
    }

    @Test
    void accountLocksAfterFiveFailedAttempts() {
        String testUser = "test_lockout_user";
        User user = new User(testUser, security.hashPassword("CorrectPass1!"), "USER");
        db.saveUser(user);

        SecurityService.LoginResult result = null;
        for (int i = 0; i < 5; i++) {
            result = security.attemptLogin(testUser, "WrongPassword");
        }
        assertTrue(result.message.contains("locked"));

        result = security.attemptLogin(testUser, "CorrectPass1!");
        assertFalse(result.success, "Correct password should still be rejected once locked");
    }

    @Test
    void unlockUserRestoresAccess() {
        String testUser = "test_unlock_user";
        User user = new User(testUser, security.hashPassword("CorrectPass1!"), "USER");
        db.saveUser(user);

        for (int i = 0; i < 5; i++) {
            security.attemptLogin(testUser, "WrongPassword");
        }
        assertTrue(db.findUserByUsername(testUser).isLocked());

        assertTrue(security.unlockUser(testUser));
        assertFalse(db.findUserByUsername(testUser).isLocked());

        SecurityService.LoginResult result = security.attemptLogin(testUser, "CorrectPass1!");
        assertTrue(result.success);
    }

    @Test
    void duplicateUsernameIsRejected() {
        String testUser = "test_duplicate_user";
        User first = new User(testUser, "somehash", "USER");
        User second = new User(testUser, "otherhash", "USER");

        assertTrue(db.saveUser(first));
        assertFalse(db.saveUser(second));
    }
}