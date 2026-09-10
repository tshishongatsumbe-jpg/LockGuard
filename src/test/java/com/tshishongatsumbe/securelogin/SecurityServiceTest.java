package com.tshishongatsumbe.securelogin;

import com.tshishongatsumbe.securelogin.Database;
import com.tshishongatsumbe.securelogin.SecurityService;
import com.tshishongatsumbe.securelogin.User;

import java.security.Security;

/**
 * Lightweight manual test runner (no JUnit
 dependency needed).

 * Run with: java -cp "out:sqlite-
 jdbc-....jar:jbcrypt-....jar"

 securelogin.SecurityServiceTest
 */
public class SecurityServiceTest {
    private static int passed = 0;
    private static int failed = 0;
    public static void main(String[] args)
    {
        Database db = new Database();
        SecurityService security = new
                SecurityService(db);

        testPasswordHashingAndVerification(security);
        testWrongPasswordFails(security);
        testPasswordStrength(security);
        testLockoutAfterFiveFailedAttempts(security, db);
        db.close();

        System.out.println("\n" + passed +
                " passed, " + failed + " failed");
    }
    private static void check(String name,
                              boolean condition) {
        if (condition) {
            passed++;
            System.out.println("PASS - " +
                    name);
        } else {
            failed++;
            System.out.println("FAIL - " +
                    name);
        }
    }
    private static void
    testPasswordHashingAndVerification(SecurityService security) {
        String hash = security.hashPassword("MyStrongPass1!");
        check("hash is not the plain password", !hash.equals("MyStrongPass1!"));
        check("correct password verifies",
                security.checkPassword("MyStrongPass1!",
                        hash));
    }
    private static void
    testWrongPasswordFails(SecurityService
                                   security) {
        String hash =
                security.hashPassword("MyStrongPass1!");

        check("wrong password fails verification",
        !security.checkPassword("WrongPassword", hash));
    }
    private static void
    testPasswordStrength(SecurityService
                                 security) {
        check("short password is weak",
                !security.isPasswordStrong("abc123"));
        check("password with no special char is weak",
        !security.isPasswordStrong("Abcdefg1"));
        check("strong password passes",
                security.isPasswordStrong("Abcdef1!"));
    }
    private static void
    testLockoutAfterFiveFailedAttempts(SecurityService security, Database db) {
        String testUser =
                "test_lockout_user";
        db.findUserByUsername(testUser); // no-op read, just to be safe
        User user = new User(testUser,
                security.hashPassword("CorrectPass1!"),
                "USER");
        db.saveUser(user);
        SecurityService.LoginResult result
                = null;
        for (int i = 0; i < 5; i++) {
            result =

                    security.attemptLogin(testUser,
                            "WrongPassword");
        }
        check("account locked after 5 failed attempts", result != null &&
                result.message.contains("locked"));
        result =
                security.attemptLogin(testUser,
                        "CorrectPass1!");
        check("correct password still rejected once locked", !result.success);
    }
}