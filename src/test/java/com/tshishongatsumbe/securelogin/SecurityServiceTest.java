package com.tshishongatsumbe.securelogin;

/**
 * Lightweight manual test runner (no JUnit dependency needed).
 */
public class SecurityServiceTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        Database db = new Database();
        SecurityService security = new SecurityService(db);

        testPasswordHashingAndVerification(security);
        testWrongPasswordFails(security);
        testPasswordStrength(security);
        testUsernameValidation(security);
        testLockoutAfterFiveFailedAttempts(security, db);
        testUnlockUser(security, db);
        testDuplicateUsernameRejected(db);

        db.close();
        System.out.println("\n" + passed + " passed, " + failed + " failed");
    }

    private static void check(String name, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("PASS - " + name);
        } else {
            failed++;
            System.out.println("FAIL - " + name);
        }
    }

    private static void testPasswordHashingAndVerification(SecurityService security) {
        String hash = security.hashPassword("MyStrongPass1!");
        check("hash is not the plain password", !hash.equals("MyStrongPass1!"));
        check("correct password verifies", security.checkPassword("MyStrongPass1!", hash));
    }

    private static void testWrongPasswordFails(SecurityService security) {
        String hash = security.hashPassword("MyStrongPass1!");
        check("wrong password fails verification", !security.checkPassword("WrongPassword", hash));
    }

    private static void testPasswordStrength(SecurityService security) {
        check("short password is weak", !security.isPasswordStrong("abc123"));
        check("password with no special char is weak", !security.isPasswordStrong("Abcdefg1"));
        check("strong password passes", security.isPasswordStrong("Abcdef1!"));
    }

    private static void testUsernameValidation(SecurityService security) {
        check("empty username is invalid", !security.isValidUsername(""));
        check("username with spaces is invalid", !security.isValidUsername("bad name"));
        check("username too short is invalid", !security.isValidUsername("ab"));
        check("username with symbols is invalid", !security.isValidUsername("bad@name"));
        check("valid username passes", security.isValidUsername("valid_user123"));
    }

    private static void testLockoutAfterFiveFailedAttempts(SecurityService security, Database db) {
        String testUser = "test_lockout_user";
        User user = new User(testUser, security.hashPassword("CorrectPass1!"), "USER");
        db.saveUser(user);

        SecurityService.LoginResult result = null;
        for (int i = 0; i < 5; i++) {
            result = security.attemptLogin(testUser, "WrongPassword");
        }
        check("account locked after 5 failed attempts", result != null && result.message.contains("locked"));

        result = security.attemptLogin(testUser, "CorrectPass1!");
        check("correct password still rejected once locked", !result.success);
    }

    private static void testUnlockUser(SecurityService security, Database db) {
        String testUser = "test_unlock_user";
        User user = new User(testUser, security.hashPassword("CorrectPass1!"), "USER");
        db.saveUser(user);

        for (int i = 0; i < 5; i++) {
            security.attemptLogin(testUser, "WrongPassword");
        }
        User locked = db.findUserByUsername(testUser);
        check("account is locked before unlock", locked.isLocked());

        boolean unlocked = security.unlockUser(testUser);
        User afterUnlock = db.findUserByUsername(testUser);
        check("unlockUser returns true", unlocked);
        check("account is unlocked after unlockUser", !afterUnlock.isLocked());

        SecurityService.LoginResult result = security.attemptLogin(testUser, "CorrectPass1!");
        check("correct password works again after unlock", result.success);
    }

    private static void testDuplicateUsernameRejected(Database db) {
        String testUser = "test_duplicate_user";
        User first = new User(testUser, "somehash", "USER");
        User second = new User(testUser, "otherhash", "USER");

        boolean firstSaved = db.saveUser(first);
        boolean secondSaved = db.saveUser(second);

        check("first registration succeeds", firstSaved);
        check("duplicate username is rejected by DB constraint", !secondSaved);
    }
}